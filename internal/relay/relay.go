// Package relay listens on the forwarded ports and sends what arrives
// through the tunnel: every TCP connection as a stream, every UDP client as
// a stream of framed datagrams (or, in direct mode, plain UDP).
package relay

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amor7/pol/internal/config"
	"github.com/amor7/pol/internal/tunnel"
)

// Dialer opens a stream to a target on the server's side.
type Dialer interface {
	Dial(target string) (net.Conn, error)
}

// UDPDialer is a mode that carries UDP itself rather than in a stream
// (direct mode).
type UDPDialer interface {
	DialUDP(target string) (net.Conn, error)
}

// retryEvery is how long a port that could not be opened waits before the
// next try. Another program may hold it for a moment while it restarts;
// giving up after one try would leave the port dead until pol restarts.
const retryEvery = 5 * time.Second

// udpIdle ends a UDP client's session after this long without a datagram.
const udpIdle = 2 * time.Minute

// Manager keeps one listener per forward and follows the configuration as
// ports are added and removed.
type Manager struct {
	log     *slog.Logger
	mu      sync.Mutex
	dialers map[string]Dialer // by mode
	ports   map[string]*port  // by Forward.Key()
}

func New(dialers map[string]Dialer, log *slog.Logger) *Manager {
	return &Manager{dialers: dialers, log: log, ports: map[string]*port{}}
}

// SetDialers switches to new tunnels (after the server or token changed);
// connections already open stay on the old ones until they end.
func (m *Manager) SetDialers(d map[string]Dialer) {
	m.mu.Lock()
	m.dialers = d
	m.mu.Unlock()
}

func (m *Manager) dialer(mode string) (Dialer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d, ok := m.dialers[mode]; ok && d != nil {
		return d, nil
	}
	switch mode {
	case config.ModeReverse:
		return nil, errors.New("reverse mode is not set up on this relay - run `pol reverse`")
	}
	return nil, errors.New(mode + " mode is not available")
}

// Apply opens what is new, closes what is gone, and updates what changed.
func (m *Manager) Apply(fs []config.Forward) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := map[string]config.Forward{}
	for _, f := range fs {
		want[f.Key()] = f
	}
	for k, p := range m.ports {
		if _, ok := want[k]; !ok {
			p.stop()
			delete(m.ports, k)
			m.log.Info("port closed", "port", k)
		}
	}
	for k, f := range want {
		if p, ok := m.ports[k]; ok {
			if p.target.Load().(string) != f.Target || p.mode.Load().(string) != f.ModeOf() {
				p.target.Store(f.Target)
				p.mode.Store(f.ModeOf())
				m.log.Info("port changed", "port", k, "target", f.Target, "mode", f.ModeOf())
			}
			continue
		}
		p := &port{m: m, n: f.Listen, udp: f.UDP(), quit: make(chan struct{}), conns: map[io.Closer]struct{}{}}
		p.target.Store(f.Target)
		p.mode.Store(f.ModeOf())
		p.err.Store("")
		m.ports[k] = p
		go p.run()
	}
}

// Close stops every port.
func (m *Manager) Close() {
	m.Apply(nil)
}

type port struct {
	m      *Manager
	n      int
	udp    bool
	target atomic.Value // string
	mode   atomic.Value // string
	err    atomic.Value // string: why the port is not open, if it is not
	open   atomic.Bool  // listening
	quit   chan struct{}
	once   sync.Once

	mu    sync.Mutex
	ln    io.Closer
	conns map[io.Closer]struct{}

	active, total, up, down atomic.Int64
}

func (p *port) key() string {
	if p.udp {
		return strconv.Itoa(p.n) + "/udp"
	}
	return strconv.Itoa(p.n) + "/tcp"
}

func (p *port) run() {
	addr := ":" + strconv.Itoa(p.n)
	for {
		var ln io.Closer
		var err error
		if p.udp {
			ln, err = net.ListenPacket("udp", addr)
		} else {
			ln, err = net.Listen("tcp", addr)
		}
		if err != nil {
			if p.err.Swap(err.Error()) != err.Error() {
				p.m.log.Warn("cannot open port, will keep trying", "port", p.key(), "err", err)
			}
			select {
			case <-p.quit:
				return
			case <-time.After(retryEvery):
				continue
			}
		}
		p.mu.Lock()
		select {
		case <-p.quit:
			p.mu.Unlock()
			ln.Close()
			return
		default:
		}
		p.ln = ln
		p.mu.Unlock()
		p.err.Store("")
		p.open.Store(true)
		p.m.log.Info("port open", "port", p.key(), "target", p.target.Load(), "mode", p.mode.Load())
		if p.udp {
			p.serveUDP(ln.(net.PacketConn))
		} else {
			p.serveTCP(ln.(net.Listener))
		}
		p.open.Store(false)
		ln.Close()
		select {
		case <-p.quit:
			return
		default: // the listener broke (rare): reopen it
		}
	}
}

func (p *port) serveTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-p.quit:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		go p.handle(c)
	}
}

func (p *port) stop() {
	p.once.Do(func() {
		close(p.quit)
		p.mu.Lock()
		if p.ln != nil {
			p.ln.Close()
		}
		for c := range p.conns {
			c.Close()
		}
		p.mu.Unlock()
		p.open.Store(false)
	})
}

func (p *port) track(c io.Closer, add bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if add {
		select {
		case <-p.quit:
			return false
		default:
		}
		p.conns[c] = struct{}{}
	} else {
		delete(p.conns, c)
	}
	return true
}

var lastDialWarn atomic.Int64

func (p *port) warnDial(target, mode string, err error) {
	// One line a minute is enough to say what is wrong.
	if now := time.Now().Unix(); now-lastDialWarn.Swap(now) > 60 {
		p.m.log.Warn("could not reach the target", "port", p.key(), "target", target, "mode", mode, "err", err)
	}
}

func (p *port) handle(c net.Conn) {
	defer c.Close()
	if !p.track(c, true) {
		return
	}
	defer p.track(c, false)
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	target, mode := p.target.Load().(string), p.mode.Load().(string)
	d, err := p.m.dialer(mode)
	var up net.Conn
	if err == nil {
		up, err = d.Dial(target)
	}
	if err != nil {
		p.warnDial(target, mode, err)
		return
	}
	defer up.Close()
	p.total.Add(1)
	p.active.Add(1)
	defer p.active.Add(-1)

	upDone := make(chan struct{})
	downDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(counter{up, &p.up}, c)
		if cw, ok := up.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		close(upDone)
	}()
	go func() {
		_, _ = io.Copy(counter{c, &p.down}, up)
		if cw, ok := c.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		close(downDone)
	}()
	// The service ending its side ends the stream; the user ending theirs
	// only means they have finished sending - the answer may still be coming.
	select {
	case <-downDone:
	case <-upDone:
		<-downDone
	}
}

// ---------------------------------------------------------------- UDP

// session is one UDP client: datagrams from it go up, answers come back.
type session struct {
	up     net.Conn
	framed bool // up is a stream of framed datagrams, not a UDP socket
	wmu    sync.Mutex
	last   atomic.Int64
}

func (s *session) send(b []byte) error {
	s.last.Store(time.Now().Unix())
	if !s.framed {
		_, err := s.up.Write(b)
		return err
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return tunnel.WriteDatagram(s.up, b)
}

func (p *port) serveUDP(pc net.PacketConn) {
	var mu sync.Mutex
	sessions := map[string]*session{}
	closeAll := func() {
		mu.Lock()
		for _, s := range sessions {
			s.up.Close()
		}
		sessions = map[string]*session{}
		mu.Unlock()
	}
	defer closeAll()

	// Sessions nobody has used for a while are ended.
	stopJanitor := make(chan struct{})
	defer close(stopJanitor)
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stopJanitor:
				return
			case <-t.C:
				cut := time.Now().Add(-udpIdle).Unix()
				mu.Lock()
				for k, s := range sessions {
					if s.last.Load() < cut {
						s.up.Close()
						delete(sessions, k)
					}
				}
				mu.Unlock()
			}
		}
	}()

	buf := make([]byte, 65536)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		key := from.String()
		mu.Lock()
		s := sessions[key]
		mu.Unlock()
		if s == nil {
			s, err = p.openSession(pc, from, func(gone *session) {
				mu.Lock()
				if sessions[key] == gone {
					delete(sessions, key)
				}
				mu.Unlock()
			})
			if err != nil {
				p.warnDial(p.target.Load().(string), p.mode.Load().(string), err)
				continue
			}
			mu.Lock()
			sessions[key] = s
			mu.Unlock()
		}
		p.up.Add(int64(n))
		if s.send(buf[:n]) != nil {
			s.up.Close()
		}
	}
}

func (p *port) openSession(pc net.PacketConn, from net.Addr, gone func(*session)) (*session, error) {
	target, mode := p.target.Load().(string), p.mode.Load().(string)
	d, err := p.m.dialer(mode)
	if err != nil {
		return nil, err
	}
	s := &session{}
	if ud, ok := d.(UDPDialer); ok {
		s.up, err = ud.DialUDP(target)
	} else {
		s.framed = true
		s.up, err = d.Dial("udp:" + target)
	}
	if err != nil {
		return nil, err
	}
	s.last.Store(time.Now().Unix())
	p.total.Add(1)
	p.active.Add(1)
	go func() {
		defer func() {
			p.active.Add(-1)
			s.up.Close()
			gone(s)
		}()
		buf := make([]byte, 65536)
		for {
			var n int
			var err error
			if s.framed {
				n, err = tunnel.ReadDatagram(s.up, buf)
			} else {
				_ = s.up.SetReadDeadline(time.Now().Add(udpIdle))
				n, err = s.up.Read(buf)
			}
			if err != nil {
				return
			}
			s.last.Store(time.Now().Unix())
			p.down.Add(int64(n))
			if _, err := pc.WriteTo(buf[:n], from); err != nil {
				return
			}
		}
	}()
	return s, nil
}

type counter struct {
	w io.Writer
	n *atomic.Int64
}

func (c counter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.n.Add(int64(n))
	return n, err
}

// PortStatus is one forward as `pol status` shows it.
type PortStatus struct {
	Listen int    `json:"listen"`
	Proto  string `json:"proto"`
	Target string `json:"target"`
	Mode   string `json:"mode"`
	Open   bool   `json:"open"`
	Err    string `json:"err,omitempty"`
	Active int64  `json:"active"`
	Total  int64  `json:"total"`
	Up     int64  `json:"up"`
	Down   int64  `json:"down"`
}

func (m *Manager) Status() []PortStatus {
	m.mu.Lock()
	out := make([]PortStatus, 0, len(m.ports))
	for _, p := range m.ports {
		proto := "tcp"
		if p.udp {
			proto = "udp"
		}
		out = append(out, PortStatus{
			Listen: p.n, Proto: proto, Target: p.target.Load().(string), Mode: p.mode.Load().(string), Open: p.open.Load(), Err: p.err.Load().(string),
			Active: p.active.Load(), Total: p.total.Load(), Up: p.up.Load(), Down: p.down.Load(),
		})
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Listen != out[j].Listen {
			return out[i].Listen < out[j].Listen
		}
		return out[i].Proto < out[j].Proto
	})
	return out
}
