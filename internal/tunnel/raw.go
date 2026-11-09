package tunnel

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
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

// The "tls" mode: one TLS connection per user connection. It is chosen
// with ALPN on the same port as the HTTP/2 tunnel. After the handshake the
// relay sends one line,
//
//	POL1 <secret> <target>\n
//
// and the server answers with one byte - rawOK or why not - and then the
// connection carries the user's bytes both ways, nothing added.
//
// Each user connection being its own TCP connection matters on paths that
// lose packets or slow down each connection on its own: there one shared
// connection is only as fast as one connection can be.
const ProtoRaw = "pol1"

const (
	rawOK byte = iota
	rawBadTarget
	rawForbidden
	rawUnreachable
)

// Pooled connections wait at most this long for their first line; relays
// throw theirs away sooner (rawPoolMaxAge) so they never send into a
// connection the server has just closed.
const (
	rawPreambleWait = 60 * time.Second
	rawPoolMaxAge   = 40 * time.Second
)

// Targets for `pol speedtest`.
const (
	speedDown = "@down:" // @down:<MB> sends MB megabytes
	speedUp   = "@up"    // swallows everything, then says how much
)

func (s *Server) raw(c *tls.Conn) {
	defer c.Close()
	ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	_ = c.SetReadDeadline(time.Now().Add(rawPreambleWait))
	br := bufio.NewReaderSize(c, 4096)
	line, err := br.ReadString('\n')
	if err != nil || len(line) > 512 {
		return
	}
	f := strings.Fields(line)
	if len(f) != 3 || f[0] != "POL1" || subtle.ConstantTimeCompare([]byte(f[1]), []byte(s.Secret)) != 1 {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	s.seenIP(ip, 0)
	target := f[2]

	if mb, ok := strings.CutPrefix(target, speedDown); ok {
		n, _ := strconv.Atoi(mb)
		_, _ = c.Write([]byte{rawOK})
		_, _ = io.CopyN(c, zeroReader{}, int64(max(1, min(n, 200)))<<20)
		_ = c.CloseWrite()
		_, _ = io.Copy(io.Discard, br) // until the relay closes
		return
	}
	if target == speedUp {
		_, _ = c.Write([]byte{rawOK})
		n, _ := io.Copy(io.Discard, br)
		_ = binary.Write(c, binary.BigEndian, n)
		return
	}

	up, code, _ := s.dialTarget(context.Background(), target)
	if up == nil {
		switch code {
		case 403:
			_, _ = c.Write([]byte{rawForbidden})
		case 502:
			_, _ = c.Write([]byte{rawUnreachable})
		default:
			_, _ = c.Write([]byte{rawBadTarget})
		}
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte{rawOK}); err != nil {
		return
	}
	if !s.trackRaw(c, true) {
		return
	}
	defer s.trackRaw(c, false)
	s.open.Add(1)
	s.total.Add(1)
	s.seenIP(ip, 1)
	defer func() {
		s.open.Add(-1)
		s.seenIP(ip, -1)
	}()
	pipe(c, br, up, &s.up, &s.down)
}

// trackRaw remembers open raw connections so Close can end them.
func (s *Server) trackRaw(c net.Conn, add bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !add {
		delete(s.raws, c)
		return true
	}
	if s.closed.Load() {
		return false
	}
	if s.raws == nil {
		s.raws = map[net.Conn]struct{}{}
	}
	s.raws[c] = struct{}{}
	return true
}

// pipe copies both ways until the service side is done: relay→service
// from r (which may hold bytes already read from relay), service→relay
// into relay. up and down count the bytes.
func pipe(relay net.Conn, r io.Reader, svc net.Conn, up, down *atomic.Int64) {
	toSvc := make(chan struct{})
	go func() {
		_, _ = io.Copy(countWriter{svc, up}, r)
		closeWrite(svc)
		close(toSvc)
	}()
	_, _ = io.Copy(countWriter{relay, down}, svc)
	closeWrite(relay)
	// The service has finished; give the relay a moment to finish too,
	// then end the connection either way.
	select {
	case <-toSvc:
	case <-time.After(5 * time.Second):
	}
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		c.Close()
	}
}

type countWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c countWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.n.Add(int64(n))
	return n, err
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// ---------------------------------------------------------------- relay side

// RawClient opens one TLS connection per stream, keeping a few already
// handshaken so a new user does not wait for the round trips.
type RawClient struct {
	addr    string
	cfg     *tls.Config
	secret  string
	log     *slog.Logger
	pool    chan pooled
	warm    int
	healthy atomic.Bool
	rtt     atomic.Int64
	lastErr atomic.Value
	open    atomic.Int64
}

type pooled struct {
	c  *tls.Conn
	at time.Time
}

func NewRawClient(server, fingerprint, secret, sni string, warm int, log *slog.Logger) *RawClient {
	if sni == "" {
		sni = "example.com"
	}
	cfg := certs.Pinned(fingerprint, sni)
	cfg.NextProtos = []string{ProtoRaw}
	r := &RawClient{addr: server, cfg: cfg, secret: secret, log: log, warm: max(0, warm), pool: make(chan pooled, max(1, warm))}
	r.lastErr.Store("")
	return r
}

func (r *RawClient) handshake(ctx context.Context) (*tls.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, headerTimeout)
	defer cancel()
	start := time.Now()
	d := tls.Dialer{NetDialer: &net.Dialer{KeepAlive: 30 * time.Second}, Config: r.cfg}
	c, err := d.DialContext(ctx, "tcp", r.addr)
	if err != nil {
		r.failed(err)
		return nil, err
	}
	tc := c.(*tls.Conn)
	if tc.ConnectionState().NegotiatedProtocol != ProtoRaw {
		tc.Close()
		err := errors.New("the server is an older pol without the tls mode - run `pol update` on it")
		r.failed(err)
		return nil, err
	}
	r.rtt.Store(int64(time.Since(start)))
	if !r.healthy.Swap(true) {
		r.log.Info("tls mode up")
	}
	r.lastErr.Store("")
	return tc, nil
}

func (r *RawClient) failed(err error) {
	if r.healthy.Swap(false) {
		r.log.Warn("tls mode down", "err", err)
	}
	r.lastErr.Store(err.Error())
}

func (r *RawClient) get() (*tls.Conn, error) {
	for {
		select {
		case p := <-r.pool:
			if time.Since(p.at) < rawPoolMaxAge {
				return p.c, nil
			}
			p.c.Close()
			continue
		default:
		}
		return r.handshake(context.Background())
	}
}

// open sends the first line and reads the answer.
func (r *RawClient) start(target string) (*tls.Conn, error) {
	c, err := r.get()
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(headerTimeout))
	if _, err := fmt.Fprintf(c, "POL1 %s %s\n", r.secret, target); err != nil {
		c.Close()
		return nil, err
	}
	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		c.Close()
		err = errors.New("the server closed the connection - is the token current? (`pol token` on the server)")
		r.failed(err)
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	switch b[0] {
	case rawOK:
		return c, nil
	case rawForbidden:
		c.Close()
		return nil, fmt.Errorf("%w: only the server's own ports may be reached", ErrRejected)
	case rawUnreachable:
		c.Close()
		return nil, fmt.Errorf("%w: nothing answers on %s", ErrRejected, target)
	default:
		c.Close()
		return nil, fmt.Errorf("%w: bad target", ErrRejected)
	}
}

// Dial opens a stream to target on the server's side.
func (r *RawClient) Dial(target string) (net.Conn, error) {
	c, err := r.start(target)
	if err != nil {
		return nil, err
	}
	r.open.Add(1)
	return &rawConn{Conn: c, done: func() { r.open.Add(-1) }}, nil
}

type rawConn struct {
	*tls.Conn
	once sync.Once
	done func()
}

func (c *rawConn) Close() error {
	c.once.Do(c.done)
	return c.Conn.Close()
}

// Watch keeps the pool filled until ctx ends.
func (r *RawClient) Watch(ctx context.Context) {
	backoff := time.Second
	for {
		// Drop connections about to age out, then top up.
		for range len(r.pool) {
			select {
			case p := <-r.pool:
				if time.Since(p.at) < rawPoolMaxAge-10*time.Second {
					r.pool <- p
				} else {
					p.c.Close()
				}
			default:
			}
		}
		for len(r.pool) < r.warm && ctx.Err() == nil {
			c, err := r.handshake(ctx)
			if err != nil {
				break
			}
			select {
			case r.pool <- pooled{c, time.Now()}:
			default:
				c.Close()
			}
		}
		wait := 5 * time.Second
		if !r.healthy.Load() {
			wait = backoff
			backoff = min(backoff*2, 30*time.Second)
		} else {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			for range len(r.pool) {
				p := <-r.pool
				p.c.Close()
			}
			return
		case <-time.After(wait):
		}
	}
}

// RawStatus is the tls mode as `pol status` shows it.
type RawStatus struct {
	Up    bool    `json:"up"`
	RTTms float64 `json:"rtt_ms"` // last handshake
	Open  int64   `json:"open"`
	Warm  int     `json:"warm"`
	Err   string  `json:"err,omitempty"`
}

func (r *RawClient) Status() RawStatus {
	return RawStatus{Up: r.healthy.Load(), RTTms: float64(r.rtt.Load()) / 1e6, Open: r.open.Load(), Warm: len(r.pool), Err: r.lastErr.Load().(string)}
}

// SpeedDown fetches mb megabytes over one tls-mode connection.
func (r *RawClient) SpeedDown(ctx context.Context, mb int) (int64, error) {
	c, err := r.start(speedDown + strconv.Itoa(mb))
	if err != nil {
		return 0, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	return io.Copy(io.Discard, c)
}

// SpeedUp sends mb megabytes over one tls-mode connection and returns
// what arrived.
func (r *RawClient) SpeedUp(ctx context.Context, mb int) (int64, error) {
	c, err := r.start(speedUp)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if _, err := io.CopyN(c, zeroReader{}, int64(mb)<<20); err != nil {
		return 0, err
	}
	_ = c.CloseWrite()
	var got int64
	err = binary.Read(c, binary.BigEndian, &got)
	return got, err
}

// ---------------------------------------------------------------- direct

// Direct is the "direct" mode: no tunnel at all, a plain TCP connection
// from the relay to the port on the server. A target on the server's own
// loopback means the server's public address.
type Direct struct {
	Host string // the server's address, as in the token
}

func (d Direct) Dial(target string) (net.Conn, error) {
	h, p, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	if loopback(h) {
		h = d.Host
	}
	return net.DialTimeout("tcp", net.JoinHostPort(h, p), 10*time.Second)
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
