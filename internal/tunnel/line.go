package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amor7/pol/internal/certs"
)

// Most modes open a stream the same way once their connection is up: the
// relay sends one line,
//
//	POL1 <secret> <target>\n
//
// the server answers one status byte, and from then on the connection
// carries the user's bytes and nothing else. The modes differ only in the
// connection underneath: TLS (tls), a WebSocket (ws), an obfuscated TCP
// connection (obfs), a QUIC stream (quic), a connection the server opened
// to the relay (reverse). split sends "SPLIT ..." on several at once.

// Pooled connections wait at most this long for their first line; relays
// throw theirs away sooner (poolMaxAge) so they never send into a
// connection the server has just closed.
const (
	rawPreambleWait = 60 * time.Second
	poolMaxAge      = 40 * time.Second
)

// serveLine reads the first line of a connection and serves it. wait bounds
// how long the line may take; onLine, if set, is called once it arrived.
func (s *Server) serveLine(c net.Conn, ip string, wait time.Duration, onLine func()) {
	_ = c.SetReadDeadline(time.Now().Add(wait))
	br := bufio.NewReaderSize(c, 4096)
	line, err := br.ReadSlice('\n')
	if err != nil || len(line) > 512 {
		c.Close()
		return
	}
	if onLine != nil {
		onLine()
	}
	_ = c.SetReadDeadline(time.Time{})
	lc := &lineConn{Conn: c, br: br}
	f := strings.Fields(string(line))
	switch {
	case len(f) == 3 && f[0] == "POL1" && s.secretOK(f[1]):
		s.serveTarget(lc, ip, f[2])
	case len(f) == 6 && f[0] == "SPLIT" && s.secretOK(f[1]):
		idx, err1 := strconv.Atoi(f[3])
		k, err2 := strconv.Atoi(f[4])
		if err1 != nil || err2 != nil {
			c.Close()
			return
		}
		s.joinSplit(lc, ip, f[2], idx, k, f[5])
	default:
		c.Close()
	}
}

func (s *Server) serveTarget(c net.Conn, ip, target string) {
	defer c.Close()
	ep, st := s.endpoint(context.Background(), target)
	if _, err := c.Write([]byte{st}); err != nil || ep == nil {
		if ep != nil {
			ep.close()
		}
		return
	}
	defer ep.close()
	if !s.track(c, true) {
		return
	}
	defer s.track(c, false)
	s.begin(ip)
	defer s.end(ip)
	ep.run(s, c, c)
}

// lineConn reads through the buffer the first line was read with.
type lineConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *lineConn) Read(p []byte) (int, error) { return c.br.Read(p) }
func (c *lineConn) CloseWrite() error          { return closeWrite(c.Conn) }

// startLine sends the first line and reads the answer.
func startLine(c net.Conn, line, target string) error {
	_ = c.SetDeadline(time.Now().Add(headerTimeout))
	if _, err := io.WriteString(c, line+"\n"); err != nil {
		return err
	}
	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return errors.New("the server closed the connection - is the token current? (`pol token` on the server)")
	}
	_ = c.SetDeadline(time.Time{})
	if b[0] != statusOK {
		return statusErr(b[0], target)
	}
	return nil
}

// ---------------------------------------------------------------- pooled dialer

// LineDialer opens one connection per stream with the line protocol,
// keeping a few connected in advance so a new user does not wait for the
// round trips of setting one up.
type LineDialer struct {
	name    string
	secret  string
	connect func(ctx context.Context) (net.Conn, error)
	log     *slog.Logger
	warm    int
	pool    chan pooled
	healthy atomic.Bool
	rtt     atomic.Int64
	lastErr atomic.Value
	open    atomic.Int64
}

type pooled struct {
	c  net.Conn
	at time.Time
}

func newLineDialer(name, secret string, warm int, log *slog.Logger, connect func(context.Context) (net.Conn, error)) *LineDialer {
	d := &LineDialer{name: name, secret: secret, connect: connect, log: log, warm: max(0, warm), pool: make(chan pooled, max(1, warm))}
	d.lastErr.Store("")
	return d
}

// NewRawClient is the tls mode: a TLS connection per stream.
func NewRawClient(server, fingerprint, secret, sni string, warm int, log *slog.Logger) *LineDialer {
	return newLineDialer("tls", secret, warm, log, tlsConnect(server, fingerprint, sni, ProtoRaw))
}

func tlsConnect(server, fingerprint, sni, alpn string) func(context.Context) (net.Conn, error) {
	if sni == "" {
		sni = "example.com"
	}
	cfg := certs.Pinned(fingerprint, sni)
	cfg.NextProtos = []string{alpn}
	return func(ctx context.Context) (net.Conn, error) {
		d := tls.Dialer{NetDialer: &net.Dialer{KeepAlive: 30 * time.Second}, Config: cfg}
		c, err := d.DialContext(ctx, "tcp", server)
		if err != nil {
			return nil, err
		}
		tc := c.(*tls.Conn)
		if tc.ConnectionState().NegotiatedProtocol != alpn {
			tc.Close()
			return nil, errors.New("the server is an older pol without this mode - run `pol update` on it")
		}
		return tc, nil
	}
}

func (d *LineDialer) fresh(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, headerTimeout)
	defer cancel()
	start := time.Now()
	c, err := d.connect(ctx)
	if err != nil {
		d.failed(err)
		return nil, err
	}
	d.rtt.Store(int64(time.Since(start)))
	if !d.healthy.Swap(true) {
		d.log.Info(d.name + " mode up")
	}
	d.lastErr.Store("")
	return c, nil
}

func (d *LineDialer) failed(err error) {
	if d.healthy.Swap(false) {
		d.log.Warn(d.name+" mode down", "err", err)
	}
	d.lastErr.Store(err.Error())
}

// get returns a connection ready for its first line, and whether it was
// made just now (a failure on a fresh one is real; on a pooled one it may
// only be stale).
func (d *LineDialer) get() (net.Conn, bool, error) {
	for {
		select {
		case p := <-d.pool:
			if time.Since(p.at) < poolMaxAge {
				return p.c, false, nil
			}
			p.c.Close()
			continue
		default:
		}
		c, err := d.fresh(context.Background())
		return c, true, err
	}
}

// Dial opens a stream to target on the server's side.
func (d *LineDialer) Dial(target string) (net.Conn, error) {
	for {
		c, fresh, err := d.get()
		if err != nil {
			return nil, err
		}
		err = startLine(c, "POL1 "+d.secret+" "+target, target)
		if err == nil {
			d.open.Add(1)
			return &countedConn{Conn: c, done: func() { d.open.Add(-1) }}, nil
		}
		c.Close()
		if errors.Is(err, ErrRejected) {
			return nil, err
		}
		if fresh {
			d.failed(err)
			return nil, err
		}
		// A pooled connection that went stale: try again with another.
	}
}

// Watch keeps the pool filled until ctx ends.
func (d *LineDialer) Watch(ctx context.Context) {
	backoff := time.Second
	for {
		for range len(d.pool) {
			select {
			case p := <-d.pool:
				if time.Since(p.at) < poolMaxAge-10*time.Second {
					d.pool <- p
				} else {
					p.c.Close()
				}
			default:
			}
		}
		for len(d.pool) < d.warm && ctx.Err() == nil {
			c, err := d.fresh(ctx)
			if err != nil {
				break
			}
			select {
			case d.pool <- pooled{c, time.Now()}:
			default:
				c.Close()
			}
		}
		wait := 5 * time.Second
		if d.warm > 0 && !d.healthy.Load() {
			wait = backoff
			backoff = min(backoff*2, 30*time.Second)
		} else {
			backoff = time.Second
		}
		if d.warm == 0 {
			// Nothing to keep ready: just check now and then that the
			// server is still reachable, so the status means something.
			wait = 30 * time.Second
			if c, err := d.fresh(ctx); err == nil {
				c.Close()
			}
		}
		select {
		case <-ctx.Done():
			for range len(d.pool) {
				p := <-d.pool
				p.c.Close()
			}
			return
		case <-time.After(wait):
		}
	}
}

func (d *LineDialer) Status() ModeStatus {
	return ModeStatus{Up: d.healthy.Load(), RTTms: float64(d.rtt.Load()) / 1e6, Open: d.open.Load(), Ready: len(d.pool), Err: d.lastErr.Load().(string)}
}

// ModeStatus is one mode as `pol status` shows it.
type ModeStatus struct {
	Mode  string  `json:"mode"`
	Up    bool    `json:"up"`
	RTTms float64 `json:"rtt_ms"` // connection setup time, or ping
	Open  int64   `json:"open"`
	Ready int     `json:"ready"` // connections waiting in a pool
	Note  string  `json:"note,omitempty"`
	Err   string  `json:"err,omitempty"`
}

// countedConn counts itself as open until closed.
type countedConn struct {
	net.Conn
	once sync.Once
	done func()
}

func (c *countedConn) Close() error {
	c.once.Do(c.done)
	return c.Conn.Close()
}

func (c *countedConn) CloseWrite() error { return closeWrite(c.Conn) }

// ---------------------------------------------------------------- direct

// Direct is the "direct" mode: no tunnel at all, a plain connection from
// the relay to the port on the server. A target on the server's own
// loopback means the server's public address.
type Direct struct {
	Host string // the server's address, as in the token
}

func (d Direct) addr(target string) (string, error) {
	h, p, err := net.SplitHostPort(target)
	if err != nil {
		return "", err
	}
	if loopback(h) {
		h = d.Host
	}
	return net.JoinHostPort(h, p), nil
}

func (d Direct) Dial(target string) (net.Conn, error) {
	a, err := d.addr(target)
	if err != nil {
		return nil, err
	}
	return net.DialTimeout("tcp", a, 10*time.Second)
}

// DialUDP opens a UDP socket to target for direct UDP forwarding.
func (d Direct) DialUDP(target string) (net.Conn, error) {
	a, err := d.addr(target)
	if err != nil {
		return nil, err
	}
	return net.Dial("udp", a)
}

func (d Direct) Status() ModeStatus {
	return ModeStatus{Up: true, Note: "straight to " + d.Host}
}

// ---------------------------------------------------------------- plumbing

// chanListener hands connections the server has already handshaken to the
// HTTP server.
type chanListener struct {
	addr net.Addr
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{addr: addr, ch: make(chan net.Conn), done: make(chan struct{})}
}

func (l *chanListener) push(c net.Conn) bool {
	select {
	case l.ch <- c:
		return true
	case <-l.done:
		return false
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return l.addr }
