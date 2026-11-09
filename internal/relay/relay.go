// Package relay listens on the forwarded ports and sends every connection
// that arrives through the tunnel.
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
)

// Dialer opens a stream to a target on the server's side.
type Dialer interface {
	Dial(target string) (net.Conn, error)
}

// retryEvery is how long a port that could not be opened waits before the
// next try. Another program may hold it for a moment while it restarts;
// giving up after one try would leave the port dead until pol restarts.
const retryEvery = 5 * time.Second

// Manager keeps one listener per forward and follows the configuration as
// ports are added and removed.
type Manager struct {
	log    *slog.Logger
	mu     sync.Mutex
	dialer Dialer
	ports  map[int]*port
}

func New(d Dialer, log *slog.Logger) *Manager {
	return &Manager{dialer: d, log: log, ports: map[int]*port{}}
}

// SetDialer switches to a new tunnel (after the server or token changed);
// connections already open stay on the old one until they end.
func (m *Manager) SetDialer(d Dialer) {
	m.mu.Lock()
	m.dialer = d
	m.mu.Unlock()
}

func (m *Manager) currentDialer() Dialer {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dialer
}

// Apply opens what is new, closes what is gone, and retargets what moved.
func (m *Manager) Apply(fs []config.Forward) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := map[int]string{}
	for _, f := range fs {
		want[f.Listen] = f.Target
	}
	for n, p := range m.ports {
		if _, ok := want[n]; !ok {
			p.stop()
			delete(m.ports, n)
			m.log.Info("port closed", "port", n)
		}
	}
	for n, target := range want {
		if p, ok := m.ports[n]; ok {
			if p.target.Load().(string) != target {
				p.target.Store(target)
				m.log.Info("port retargeted", "port", n, "target", target)
			}
			continue
		}
		p := &port{m: m, n: n, quit: make(chan struct{}), conns: map[net.Conn]struct{}{}}
		p.target.Store(target)
		p.err.Store("")
		m.ports[n] = p
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
	target atomic.Value // string
	err    atomic.Value // string: why the port is not open, if it is not
	open   atomic.Bool  // listening
	quit   chan struct{}
	once   sync.Once

	mu    sync.Mutex
	ln    net.Listener
	conns map[net.Conn]struct{}

	active, total, up, down atomic.Int64
}

func (p *port) run() {
	addr := ":" + strconv.Itoa(p.n)
	for {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			if p.err.Swap(err.Error()) != err.Error() {
				p.m.log.Warn("cannot open port, will keep trying", "port", p.n, "err", err)
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
		p.m.log.Info("port open", "port", p.n, "target", p.target.Load())
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
				// The listener broke (rare): reopen it.
				p.open.Store(false)
				ln.Close()
				break
			}
			go p.handle(c)
		}
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

func (p *port) track(c net.Conn, add bool) bool {
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
	target := p.target.Load().(string)
	up, err := p.m.currentDialer().Dial(target)
	if err != nil {
		// One line a minute is enough to say what is wrong.
		if now := time.Now().Unix(); now-lastDialWarn.Swap(now) > 60 {
			p.m.log.Warn("could not reach the target through the tunnel", "port", p.n, "target", target, "err", err)
		}
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
	Target string `json:"target"`
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
	for n, p := range m.ports {
		out = append(out, PortStatus{
			Listen: n, Target: p.target.Load().(string), Open: p.open.Load(), Err: p.err.Load().(string),
			Active: p.active.Load(), Total: p.total.Load(), Up: p.up.Load(), Down: p.down.Load(),
		})
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Listen < out[j].Listen })
	return out
}
