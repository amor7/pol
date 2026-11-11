//go:build linux

package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
)

// The faketcp mode: KCP's packets, each sent as a TCP segment over a raw
// socket. The two ends go through a real-looking three-way handshake, so
// firewalls and NATs that follow TCP connections let the flow through, and
// networks that slow UDP down see TCP instead. The kernel's own TCP stack
// would answer these segments with resets, so pol drops outgoing resets for
// the port with an iptables rule while the mode is in use.

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
)

// FakeTCPSupported says whether faketcp can run here.
func FakeTCPSupported() error {
	if _, err := exec.LookPath("iptables"); err != nil {
		return errors.New("faketcp needs iptables")
	}
	return nil
}

// fakeTCP is one end's raw socket: it sends and receives segments for one
// local port.
type fakeTCP struct {
	raw   *net.IPConn
	pc    *ipv4.PacketConn
	lport uint16
	rule  []string // the iptables rule to remove on close
	once  sync.Once
}

func openFakeTCP(lport uint16, rule []string) (*fakeTCP, error) {
	raw, err := net.ListenIP("ip4:tcp", nil)
	if err != nil {
		return nil, err
	}
	pc := ipv4.NewPacketConn(raw)
	if err := pc.SetControlMessage(ipv4.FlagDst, true); err != nil {
		raw.Close()
		return nil, err
	}
	f := &fakeTCP{raw: raw, pc: pc, lport: lport, rule: rule}
	if rule != nil {
		if exec.Command("iptables", append([]string{"-C"}, rule...)...).Run() != nil {
			if out, err := exec.Command("iptables", append([]string{"-I"}, rule...)...).CombinedOutput(); err != nil {
				raw.Close()
				return nil, errors.New("faketcp: iptables: " + string(out))
			}
		} else {
			f.rule = nil // someone else's rule: leave it alone
		}
	}
	return f, nil
}

func (f *fakeTCP) close() {
	f.once.Do(func() {
		f.raw.Close()
		if f.rule != nil {
			_ = exec.Command("iptables", append([]string{"-D"}, f.rule...)...).Run()
		}
	})
}

type segment struct {
	src, dst     net.IP
	sport, dport uint16
	seq, ack     uint32
	flags        byte
	payload      []byte
}

// read returns the next segment addressed to this end's port.
func (f *fakeTCP) read(buf []byte) (segment, error) {
	for {
		n, cm, src, err := f.pc.ReadFrom(buf)
		if err != nil {
			return segment{}, err
		}
		if n < 20 {
			continue
		}
		b := buf[:n]
		if binary.BigEndian.Uint16(b[2:]) != f.lport {
			continue
		}
		off := int(b[12]>>4) * 4
		if off < 20 || off > n {
			continue
		}
		s := segment{sport: binary.BigEndian.Uint16(b), dport: f.lport, seq: binary.BigEndian.Uint32(b[4:]), ack: binary.BigEndian.Uint32(b[8:]), flags: b[13], payload: b[off:]}
		if ip, ok := src.(*net.IPAddr); ok {
			s.src = ip.IP.To4()
		}
		if cm != nil {
			s.dst = cm.Dst.To4()
		}
		return s, nil
	}
}

func (f *fakeTCP) write(s segment) error {
	b := make([]byte, 20+len(s.payload))
	binary.BigEndian.PutUint16(b, s.sport)
	binary.BigEndian.PutUint16(b[2:], s.dport)
	binary.BigEndian.PutUint32(b[4:], s.seq)
	binary.BigEndian.PutUint32(b[8:], s.ack)
	b[12] = 5 << 4
	b[13] = s.flags
	binary.BigEndian.PutUint16(b[14:], 64240) // window
	copy(b[20:], s.payload)
	binary.BigEndian.PutUint16(b[16:], tcpChecksum(s.src, s.dst, b))
	_, err := f.raw.WriteToIP(b, &net.IPAddr{IP: s.dst})
	return err
}

func tcpChecksum(src, dst net.IP, seg []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(src.To4())
	add(dst.To4())
	sum += 6 + uint32(len(seg))
	add(seg)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// localIPFor is the address this machine sends from towards dst.
func localIPFor(dst net.IP) (net.IP, error) {
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: dst, Port: 9})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.To4(), nil
}

// ---------------------------------------------------------------- server

type ftPeer struct {
	addr     *net.UDPAddr // stands for the peer in KCP's eyes
	ip       net.IP
	port     uint16
	local    net.IP
	seq, ack atomic.Uint32
}

// ftServer is the server's faketcp port as a packet connection.
type ftServer struct {
	f     *fakeTCP
	mu    sync.Mutex
	peers map[string]*ftPeer
	in    chan inPkt
	done  chan struct{}
}

// ListenFakeTCP listens for faketcp on TCP port port.
func ListenFakeTCP(port int) (net.PacketConn, error) {
	if err := FakeTCPSupported(); err != nil {
		return nil, err
	}
	p := strconv.Itoa(port)
	f, err := openFakeTCP(uint16(port), []string{"OUTPUT", "-p", "tcp", "--sport", p, "--tcp-flags", "RST", "RST", "-j", "DROP"})
	if err != nil {
		return nil, err
	}
	s := &ftServer{f: f, peers: map[string]*ftPeer{}, in: make(chan inPkt, 1024), done: make(chan struct{})}
	go s.loop()
	return s, nil
}

func (s *ftServer) peer(seg segment) *ftPeer {
	key := seg.src.String() + ":" + strconv.Itoa(int(seg.sport))
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.peers[key]
	if p == nil {
		p = &ftPeer{addr: &net.UDPAddr{IP: seg.src, Port: int(seg.sport)}, ip: seg.src, port: seg.sport, local: seg.dst}
		p.seq.Store(rand.Uint32())
		s.peers[key] = p
	}
	return p
}

func (s *ftServer) loop() {
	buf := make([]byte, 65536)
	for {
		seg, err := s.f.read(buf)
		if err != nil {
			close(s.done)
			return
		}
		if seg.src == nil || seg.dst == nil || seg.flags&tcpRST != 0 {
			continue
		}
		p := s.peer(seg)
		if seg.flags&tcpSYN != 0 {
			// Answer the handshake; a repeated SYN gets the same answer.
			p.ack.Store(seg.seq + 1)
			_ = s.f.write(segment{src: p.local, dst: p.ip, sport: s.f.lport, dport: p.port, seq: p.seq.Load(), ack: seg.seq + 1, flags: tcpSYN | tcpACK})
			continue
		}
		if len(seg.payload) == 0 {
			continue
		}
		p.ack.Store(seg.seq + uint32(len(seg.payload)))
		b := make([]byte, len(seg.payload))
		copy(b, seg.payload)
		select {
		case s.in <- inPkt{b: b, from: p.addr}:
		default: // KCP is behind; it resends
		}
	}
}

func (s *ftServer) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case pk := <-s.in:
		return copy(b, pk.b), pk.from, nil
	case <-s.done:
		return 0, nil, net.ErrClosed
	}
}

func (s *ftServer) WriteTo(b []byte, addr net.Addr) (int, error) {
	s.mu.Lock()
	p := s.peers[addr.String()]
	s.mu.Unlock()
	if p == nil {
		return 0, errors.New("faketcp: unknown peer")
	}
	seq := p.seq.Add(uint32(len(b))) - uint32(len(b))
	if err := s.f.write(segment{src: p.local, dst: p.ip, sport: s.f.lport, dport: p.port, seq: seq + 1, ack: p.ack.Load(), flags: tcpPSH | tcpACK, payload: b}); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (s *ftServer) Close() error                     { s.f.close(); return nil }
func (s *ftServer) LocalAddr() net.Addr              { return &net.TCPAddr{Port: int(s.f.lport)} }
func (s *ftServer) SetDeadline(time.Time) error      { return nil }
func (s *ftServer) SetReadDeadline(time.Time) error  { return nil }
func (s *ftServer) SetWriteDeadline(time.Time) error { return nil }

// ---------------------------------------------------------------- client

type ftClient struct {
	f        *fakeTCP
	remote   net.IP
	rport    uint16
	local    net.IP
	fixed    *net.UDPAddr
	seq, ack atomic.Uint32
	in       chan []byte
	done     chan struct{}
	estab    chan struct{}
	once     sync.Once
}

func dialFakeTCP(ctx context.Context, host string, port int) (*ftClient, error) {
	if err := FakeTCPSupported(); err != nil {
		return nil, err
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	var rip net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			rip = ip.To4()
			break
		}
	}
	if rip == nil {
		return nil, errors.New("faketcp: " + host + " has no IPv4 address")
	}
	local, err := localIPFor(rip)
	if err != nil {
		return nil, err
	}
	lport := uint16(20000 + rand.IntN(40000))
	rule := []string{"OUTPUT", "-p", "tcp", "-d", rip.String(), "--dport", strconv.Itoa(port), "--sport", strconv.Itoa(int(lport)), "--tcp-flags", "RST", "RST", "-j", "DROP"}
	f, err := openFakeTCP(lport, rule)
	if err != nil {
		return nil, err
	}
	c := &ftClient{f: f, remote: rip, rport: uint16(port), local: local, fixed: &net.UDPAddr{IP: rip, Port: port}, in: make(chan []byte, 1024), done: make(chan struct{}), estab: make(chan struct{})}
	c.seq.Store(rand.Uint32())
	go c.loop()
	// The handshake: SYN until a SYN-ACK comes, then ACK.
	for try := 0; ; try++ {
		_ = f.write(segment{src: local, dst: rip, sport: lport, dport: c.rport, seq: c.seq.Load(), flags: tcpSYN})
		select {
		case <-c.estab:
			c.seq.Add(1)
			_ = f.write(segment{src: local, dst: rip, sport: lport, dport: c.rport, seq: c.seq.Load(), ack: c.ack.Load(), flags: tcpACK})
			return c, nil
		case <-time.After(2 * time.Second):
			if try >= 3 {
				c.Close()
				return nil, errors.New("faketcp: no answer from the server (is TCP " + strconv.Itoa(port) + " open there?)")
			}
		case <-ctx.Done():
			c.Close()
			return nil, ctx.Err()
		}
	}
}

func (c *ftClient) loop() {
	buf := make([]byte, 65536)
	established := false
	for {
		seg, err := c.f.read(buf)
		if err != nil {
			c.once.Do(func() { close(c.done) })
			return
		}
		if !seg.src.Equal(c.remote) || seg.sport != c.rport || seg.flags&tcpRST != 0 {
			continue
		}
		if seg.flags&(tcpSYN|tcpACK) == tcpSYN|tcpACK {
			c.ack.Store(seg.seq + 1)
			if !established {
				established = true
				close(c.estab)
			}
			continue
		}
		if len(seg.payload) == 0 {
			continue
		}
		c.ack.Store(seg.seq + uint32(len(seg.payload)))
		b := make([]byte, len(seg.payload))
		copy(b, seg.payload)
		select {
		case c.in <- b:
		default:
		}
	}
}

func (c *ftClient) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-c.in:
		return copy(b, p), c.fixed, nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	}
}

func (c *ftClient) WriteTo(b []byte, _ net.Addr) (int, error) {
	seq := c.seq.Add(uint32(len(b))) - uint32(len(b))
	if err := c.f.write(segment{src: c.local, dst: c.remote, sport: c.f.lport, dport: c.rport, seq: seq, ack: c.ack.Load(), flags: tcpPSH | tcpACK, payload: b}); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *ftClient) Close() error {
	c.f.close()
	c.once.Do(func() { close(c.done) })
	return nil
}

func (c *ftClient) LocalAddr() net.Addr              { return &net.TCPAddr{IP: c.local, Port: int(c.f.lport)} }
func (c *ftClient) SetDeadline(time.Time) error      { return nil }
func (c *ftClient) SetReadDeadline(time.Time) error  { return nil }
func (c *ftClient) SetWriteDeadline(time.Time) error { return nil }

// NewFakeTCPClient is the faketcp mode's relay side.
func NewFakeTCPClient(host string, port int, secret string, log *slog.Logger) *KCPClient {
	return newKCPClient("faketcp", secret, ProfileFakeTCP, log, func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		c, err := dialFakeTCP(ctx, host, port)
		if err != nil {
			return nil, nil, err
		}
		return c, c.fixed, nil
	})
}

var _ = slog.Default
