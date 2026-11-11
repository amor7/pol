package tunnel

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// The hop mode: KCP over UDP, sent to a different port of a range on the
// server every half minute or so. Where a network slows a UDP flow down
// once it has run on one port for a while, the flow keeps starting afresh.
// The server listens on every port of the range; the relay keeps one local
// port, so to the server it is one peer throughout.

const hopEvery = 30 * time.Second

// ListenHop opens every UDP port from lo to hi (inclusive) on host and
// joins them into one packet connection. Ports that cannot be opened are
// left out; the relay notices silence on those and moves on.
func ListenHop(host string, lo, hi int, log *slog.Logger) (net.PacketConn, error) {
	m := &multiPC{in: make(chan inPkt, 1024), done: make(chan struct{})}
	var missed []int
	for p := lo; p <= hi; p++ {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host), Port: p})
		if err != nil {
			missed = append(missed, p)
			continue
		}
		_ = c.SetReadBuffer(1 << 20)
		_ = c.SetWriteBuffer(1 << 20)
		m.socks = append(m.socks, c)
	}
	if len(m.socks) == 0 {
		return nil, errors.New("hop: none of the ports " + strconv.Itoa(lo) + "-" + strconv.Itoa(hi) + " could be opened")
	}
	if len(missed) > 0 {
		log.Warn("hop: some ports of the range are in use and left out", "ports", len(missed))
	}
	for _, c := range m.socks {
		go m.read(c)
	}
	return m, nil
}

type inPkt struct {
	b    []byte
	from *net.UDPAddr
	sock *net.UDPConn
}

// multiPC is many UDP sockets seen as one. Replies go out of the socket
// the peer last wrote to, as NATs and firewalls on the way expect.
type multiPC struct {
	socks []*net.UDPConn
	in    chan inPkt
	last  sync.Map // peer addr string -> *net.UDPConn
	done  chan struct{}
	once  sync.Once
}

func (m *multiPC) read(c *net.UDPConn) {
	buf := make([]byte, 65536)
	for {
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			return
		}
		b := make([]byte, n)
		copy(b, buf[:n])
		select {
		case m.in <- inPkt{b, from, c}:
		case <-m.done:
			return
		}
	}
}

func (m *multiPC) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pk := <-m.in:
		m.last.Store(pk.from.String(), pk.sock)
		return copy(p, pk.b), pk.from, nil
	case <-m.done:
		return 0, nil, net.ErrClosed
	}
}

func (m *multiPC) WriteTo(p []byte, addr net.Addr) (int, error) {
	sock := m.socks[0]
	if s, ok := m.last.Load(addr.String()); ok {
		sock = s.(*net.UDPConn)
	}
	return sock.WriteTo(p, addr)
}

func (m *multiPC) Close() error {
	m.once.Do(func() {
		close(m.done)
		for _, c := range m.socks {
			c.Close()
		}
	})
	return nil
}

func (m *multiPC) LocalAddr() net.Addr              { return m.socks[0].LocalAddr() }
func (m *multiPC) SetDeadline(time.Time) error      { return nil }
func (m *multiPC) SetReadDeadline(time.Time) error  { return nil }
func (m *multiPC) SetWriteDeadline(time.Time) error { return nil }

// hopConn sends to a port of the range that changes now and then, and
// reports every answer as coming from one fixed address, which is what KCP
// expects of its peer.
type hopConn struct {
	*net.UDPConn
	host    net.IP
	lo, hi  int
	cur     atomic.Int32
	since   atomic.Int64 // when cur was chosen
	lastIn  atomic.Int64 // when anything last arrived
	fixed   *net.UDPAddr
	stop    chan struct{}
	stopped sync.Once
}

func newHopConn(host string, lo, hi int) (*hopConn, error) {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, errors.New("hop: cannot resolve " + host)
	}
	c, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	h := &hopConn{UDPConn: c, host: ips[0], lo: lo, hi: hi, fixed: &net.UDPAddr{IP: ips[0], Port: lo}, stop: make(chan struct{})}
	h.move()
	go h.rotate()
	return h, nil
}

func (h *hopConn) move() {
	h.cur.Store(int32(h.lo + rand.IntN(h.hi-h.lo+1)))
	h.since.Store(time.Now().UnixMilli())
}

// rotate moves on every hopEvery, and sooner when a port stays silent - it
// may be one the server could not open.
func (h *hopConn) rotate() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-h.stop:
			return
		case <-t.C:
			now := time.Now().UnixMilli()
			since := h.since.Load()
			age := time.Duration(now-since) * time.Millisecond
			silent := h.lastIn.Load() < since
			if age >= hopEvery || (silent && age >= 3*time.Second) {
				h.move()
			}
		}
	}
}

func (h *hopConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return h.UDPConn.WriteTo(p, &net.UDPAddr{IP: h.host, Port: int(h.cur.Load())})
}

func (h *hopConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, from, err := h.UDPConn.ReadFromUDP(p)
		if err != nil {
			return 0, nil, err
		}
		if !from.IP.Equal(h.host) || from.Port < h.lo || from.Port > h.hi {
			continue
		}
		h.lastIn.Store(time.Now().UnixMilli())
		return n, h.fixed, nil
	}
}

func (h *hopConn) Close() error {
	h.stopped.Do(func() { close(h.stop) })
	return h.UDPConn.Close()
}

// NewHopClient is the hop mode's relay side: host is the server, lo-hi its
// port range.
func NewHopClient(host string, lo, hi int, secret string, log *slog.Logger) *KCPClient {
	return newKCPClient("hop", secret, ProfileHop, log, func(context.Context) (net.PacketConn, net.Addr, error) {
		h, err := newHopConn(host, lo, hi)
		if err != nil {
			return nil, nil, err
		}
		return h, h.fixed, nil
	})
}
