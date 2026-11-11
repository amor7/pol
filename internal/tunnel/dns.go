package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// The dns mode: KCP's packets inside DNS. The relay asks a resolver - any
// resolver it can reach, an Iranian one included - for TXT records of names
// under a domain whose name server is the pol server; the data going up is
// encoded in the names asked for, the data coming down is in the answers.
// The resolver passes both along as it would any lookup. It is slow - each
// query carries a hundred bytes or so - but it only needs DNS to work.
//
// A name asked for is base32 of  client id (8) | nonce (2) | packet , split
// into labels, then the domain. The nonce keeps every name new so nothing
// is answered from a cache. An answer holds any number of
// length (2) | packet  in its TXT strings.

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

const (
	dnsHeader    = 10          // client id + nonce
	dnsServerMTU = 800         // packet bytes per answer
	dnsHold      = time.Second // an empty poll waits this long for data
	dnsPollsIdle = 1           // queries kept in flight when quiet
	dnsPollsBusy = 24          // and when data is moving
	dnsQueryWait = 4 * time.Second
)

// DNSUpMTU is how many packet bytes fit in one query under domain.
func DNSUpMTU(domain string) int {
	avail := 253 - len(strings.TrimSuffix(domain, ".")) - 1
	chars := avail - avail/64 // a dot per 63 characters
	return chars*5/8 - dnsHeader
}

func fqdn(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	if !strings.HasSuffix(d, ".") {
		d += "."
	}
	return d
}

// dnsAddr stands for a relay in KCP's eyes.
type dnsAddr string

func (a dnsAddr) Network() string { return "dns" }
func (a dnsAddr) String() string  { return string(a) }

// ---------------------------------------------------------------- server

type dnsPeer struct {
	queue chan []byte // packets waiting for an answer to carry them
	seen  atomic.Int64
}

// dnsServer answers queries under its domain and is, to KCP, a packet
// connection.
type dnsServer struct {
	domain string
	pc     net.PacketConn
	mu     sync.Mutex
	peers  map[string]*dnsPeer
	in     chan dnsIn
	done   chan struct{}
	once   sync.Once
}

type dnsIn struct {
	b  []byte
	id string
}

// ListenDNS answers dns-mode queries for domain on pc.
func ListenDNS(pc net.PacketConn, domain string) net.PacketConn {
	s := &dnsServer{domain: fqdn(domain), pc: pc, peers: map[string]*dnsPeer{}, in: make(chan dnsIn, 1024), done: make(chan struct{})}
	go s.loop()
	go s.janitor()
	return s
}

func (s *dnsServer) peer(id string) *dnsPeer {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.peers[id]
	if p == nil {
		p = &dnsPeer{queue: make(chan []byte, 512)}
		s.peers[id] = p
	}
	p.seen.Store(time.Now().Unix())
	return p
}

func (s *dnsServer) janitor() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			cut := time.Now().Add(-5 * time.Minute).Unix()
			s.mu.Lock()
			for id, p := range s.peers {
				if p.seen.Load() < cut {
					delete(s.peers, id)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *dnsServer) loop() {
	buf := make([]byte, 4096)
	for {
		n, from, err := s.pc.ReadFrom(buf)
		if err != nil {
			s.once.Do(func() { close(s.done) })
			return
		}
		var p dnsmessage.Parser
		h, err := p.Start(buf[:n])
		if err != nil || h.Response {
			continue
		}
		q, err := p.Question()
		if err != nil {
			continue
		}
		name := strings.ToLower(q.Name.String())
		if !strings.HasSuffix(name, "."+s.domain) || q.Type != dnsmessage.TypeTXT {
			go s.answer(from, h, q, nil, dnsmessage.RCodeNameError)
			continue
		}
		raw, err := b32.DecodeString(strings.ToUpper(strings.ReplaceAll(strings.TrimSuffix(name, "."+s.domain), ".", "")))
		if err != nil || len(raw) < dnsHeader {
			go s.answer(from, h, q, nil, dnsmessage.RCodeNameError)
			continue
		}
		id := hex.EncodeToString(raw[:8])
		peer := s.peer(id)
		if pkt := raw[dnsHeader:]; len(pkt) > 0 {
			select {
			case s.in <- dnsIn{b: append([]byte(nil), pkt...), id: id}:
			default:
			}
		}
		go s.reply(from, h, q, peer)
	}
}

// reply answers a query with whatever is waiting for that relay, waiting a
// little for something if nothing is.
func (s *dnsServer) reply(to net.Addr, h dnsmessage.Header, q dnsmessage.Question, p *dnsPeer) {
	var data []byte
	add := func(pkt []byte) bool {
		if len(data)+2+len(pkt) > dnsServerMTU+2 {
			return false
		}
		data = binary.BigEndian.AppendUint16(data, uint16(len(pkt)))
		data = append(data, pkt...)
		return true
	}
	select {
	case pkt := <-p.queue:
		add(pkt)
	case <-time.After(dnsHold):
	case <-s.done:
		return
	}
	for more := true; more; {
		select {
		case pkt := <-p.queue:
			if !add(pkt) {
				// Does not fit: put it back for the next answer.
				select {
				case p.queue <- pkt:
				default:
				}
				more = false
			}
		default:
			more = false
		}
	}
	s.answer(to, h, q, data, dnsmessage.RCodeSuccess)
}

func (s *dnsServer) answer(to net.Addr, h dnsmessage.Header, q dnsmessage.Question, data []byte, rc dnsmessage.RCode) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionDesired: h.RecursionDesired, RCode: rc})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(q)
	if data != nil {
		_ = b.StartAnswers()
		var txt []string
		for len(data) > 0 {
			n := min(len(data), 255)
			txt = append(txt, string(data[:n]))
			data = data[n:]
		}
		_ = b.TXTResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 0}, dnsmessage.TXTResource{TXT: txt})
	}
	msg, err := b.Finish()
	if err == nil {
		_, _ = s.pc.WriteTo(msg, to)
	}
}

func (s *dnsServer) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case pk := <-s.in:
		return copy(b, pk.b), dnsAddr(pk.id), nil
	case <-s.done:
		return 0, nil, net.ErrClosed
	}
}

func (s *dnsServer) WriteTo(b []byte, addr net.Addr) (int, error) {
	s.mu.Lock()
	p := s.peers[addr.String()]
	s.mu.Unlock()
	if p == nil {
		return len(b), nil
	}
	select {
	case p.queue <- append([]byte(nil), b...):
	default: // full: KCP resends
	}
	return len(b), nil
}

func (s *dnsServer) Close() error {
	s.once.Do(func() { close(s.done) })
	return s.pc.Close()
}

func (s *dnsServer) LocalAddr() net.Addr              { return s.pc.LocalAddr() }
func (s *dnsServer) SetDeadline(time.Time) error      { return nil }
func (s *dnsServer) SetReadDeadline(time.Time) error  { return nil }
func (s *dnsServer) SetWriteDeadline(time.Time) error { return nil }

// ---------------------------------------------------------------- client

type dnsClient struct {
	resolver *net.UDPAddr
	domain   string
	id       [8]byte
	conn     *net.UDPConn
	out      chan []byte
	in       chan []byte
	mu       sync.Mutex
	pending  map[uint16]time.Time
	busy     atomic.Int64 // when data last moved
	done     chan struct{}
	once     sync.Once
}

func dialDNS(resolver, domain string) (*dnsClient, error) {
	if !strings.Contains(resolver, ":") || strings.Count(resolver, ":") > 1 && !strings.HasPrefix(resolver, "[") {
		resolver = net.JoinHostPort(resolver, "53")
	}
	ra, err := net.ResolveUDPAddr("udp", resolver)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	c := &dnsClient{resolver: ra, domain: fqdn(domain), conn: conn, out: make(chan []byte, 512), in: make(chan []byte, 1024), pending: map[uint16]time.Time{}, done: make(chan struct{})}
	_, _ = rand.Read(c.id[:])
	go c.recv()
	go c.send()
	return c, nil
}

func (c *dnsClient) inflight() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for id, at := range c.pending {
		if now.Sub(at) > dnsQueryWait {
			delete(c.pending, id)
		}
	}
	return len(c.pending)
}

func (c *dnsClient) query(pkt []byte) {
	raw := make([]byte, dnsHeader+len(pkt))
	copy(raw, c.id[:])
	_, _ = rand.Read(raw[8:dnsHeader])
	copy(raw[dnsHeader:], pkt)
	enc := strings.ToLower(b32.EncodeToString(raw))
	var labels []string
	for len(enc) > 63 {
		labels = append(labels, enc[:63])
		enc = enc[63:]
	}
	labels = append(labels, enc)
	name, err := dnsmessage.NewName(strings.Join(labels, ".") + "." + c.domain)
	if err != nil {
		return
	}
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET})
	_ = b.StartAdditionals()
	var opt dnsmessage.ResourceHeader
	_ = opt.SetEDNS0(1232, dnsmessage.RCodeSuccess, false)
	_ = b.OPTResource(opt, dnsmessage.OPTResource{})
	msg, err := b.Finish()
	if err != nil {
		return
	}
	c.mu.Lock()
	c.pending[id] = time.Now()
	c.mu.Unlock()
	_, _ = c.conn.WriteToUDP(msg, c.resolver)
}

// send keeps queries in flight: packets when there are some, empty polls
// otherwise, so the server always has a query to answer with data.
func (c *dnsClient) send() {
	for {
		limit := dnsPollsIdle
		if time.Since(time.Unix(0, c.busy.Load())) < 2*time.Second {
			limit = dnsPollsBusy
		}
		select {
		case <-c.done:
			return
		case pkt := <-c.out:
			c.busy.Store(time.Now().UnixNano())
			c.query(pkt)
			continue
		default:
		}
		if c.inflight() < limit {
			c.query(nil)
			continue
		}
		select {
		case <-c.done:
			return
		case pkt := <-c.out:
			c.busy.Store(time.Now().UnixNano())
			c.query(pkt)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (c *dnsClient) recv() {
	buf := make([]byte, 4096)
	for {
		n, _, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			c.once.Do(func() { close(c.done) })
			return
		}
		var p dnsmessage.Parser
		h, err := p.Start(buf[:n])
		if err != nil || !h.Response {
			continue
		}
		c.mu.Lock()
		_, ok := c.pending[h.ID]
		delete(c.pending, h.ID)
		c.mu.Unlock()
		if !ok {
			continue
		}
		_ = p.SkipAllQuestions()
		for {
			ah, err := p.AnswerHeader()
			if err != nil {
				break
			}
			if ah.Type != dnsmessage.TypeTXT {
				_ = p.SkipAnswer()
				continue
			}
			txt, err := p.TXTResource()
			if err != nil {
				break
			}
			data := []byte(strings.Join(txt.TXT, ""))
			for len(data) >= 2 {
				l := int(binary.BigEndian.Uint16(data))
				if 2+l > len(data) {
					break
				}
				if l > 0 {
					c.busy.Store(time.Now().UnixNano())
					select {
					case c.in <- append([]byte(nil), data[2:2+l]...):
					default:
					}
				}
				data = data[2+l:]
			}
		}
	}
}

var dnsPeerAddr = dnsAddr("dns")

func (c *dnsClient) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-c.in:
		return copy(b, p), dnsPeerAddr, nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	}
}

func (c *dnsClient) WriteTo(b []byte, _ net.Addr) (int, error) {
	select {
	case c.out <- append([]byte(nil), b...):
	case <-c.done:
		return 0, net.ErrClosed
	}
	return len(b), nil
}

func (c *dnsClient) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.conn.Close()
}

func (c *dnsClient) LocalAddr() net.Addr              { return c.conn.LocalAddr() }
func (c *dnsClient) SetDeadline(time.Time) error      { return nil }
func (c *dnsClient) SetReadDeadline(time.Time) error  { return nil }
func (c *dnsClient) SetWriteDeadline(time.Time) error { return nil }

// NewDNSClient is the dns mode's relay side: queries for names under domain
// go to resolver (host or host:port).
func NewDNSClient(resolver, domain, secret string, log *slog.Logger) *KCPClient {
	p := ProfileDNS
	p.MTU = DNSUpMTU(domain)
	k := newKCPClient("dns", secret, p, log, func(context.Context) (net.PacketConn, net.Addr, error) {
		if resolver == "" {
			return nil, nil, errors.New("dns mode: no resolver set")
		}
		c, err := dialDNS(resolver, domain)
		if err != nil {
			return nil, nil, err
		}
		return c, dnsPeerAddr, nil
	})
	return k
}
