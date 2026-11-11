package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/amor7/pol/internal/certs"
)

// The quic mode: one QUIC connection over UDP, each user connection a QUIC
// stream in it. Unlike HTTP/2, a lost packet only holds up the stream it
// belonged to, and QUIC recovers from loss on its own terms rather than
// TCP's. It listens on the tunnel port's number, over UDP. Inside each
// stream the line protocol runs as in the other modes.

func quicConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:           15 * time.Second,
		MaxIdleTimeout:                 60 * time.Second,
		KeepAlivePeriod:                20 * time.Second,
		MaxIncomingStreams:             8192,
		InitialStreamReceiveWindow:     1 << 20,
		MaxStreamReceiveWindow:         16 << 20,
		InitialConnectionReceiveWindow: 4 << 20,
		MaxConnectionReceiveWindow:     connWindow,
	}
}

// ServeQUIC answers quic-mode relays on addr (UDP) until Close.
func (s *Server) ServeQUIC(addr string, cert tls.Certificate) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	return s.ServeQUICConn(pc, cert)
}

// ServeQUICConn is ServeQUIC on a socket already open.
func (s *Server) ServeQUICConn(pc net.PacketConn, cert tls.Certificate) error {
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3", ProtoQUIC}, MinVersion: tls.VersionTLS13}
	ln, err := quic.Listen(pc, tlsCfg, quicConfig())
	if err != nil {
		pc.Close()
		return err
	}
	// As with KCP, closing the listener leaves the socket open: close both.
	if !s.addCloser(pc) {
		ln.Close()
		pc.Close()
		return nil
	}
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		ln.Close()
		return nil
	}
	s.qln = ln
	s.mu.Unlock()
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return nil
		}
		go func() {
			ip := hostOf(conn.RemoteAddr())
			for {
				st, err := conn.AcceptStream(context.Background())
				if err != nil {
					return
				}
				go s.serveLine(&quicStream{Stream: st, conn: conn}, ip, 15*time.Second, nil)
			}
		}()
	}
}

// quicStream is a QUIC stream as a net.Conn.
type quicStream struct {
	*quic.Stream
	conn *quic.Conn
	once sync.Once
}

func (q *quicStream) CloseWrite() error { return q.Stream.Close() }

func (q *quicStream) Close() error {
	q.once.Do(func() {
		q.Stream.CancelRead(0)
		_ = q.Stream.Close()
	})
	return nil
}

func (q *quicStream) LocalAddr() net.Addr  { return q.conn.LocalAddr() }
func (q *quicStream) RemoteAddr() net.Addr { return q.conn.RemoteAddr() }

// QUICClient is the quic mode's relay side: one connection, redialled when
// it dies, with a stream per user connection.
type QUICClient struct {
	addr    string
	tlsCfg  *tls.Config
	secret  string
	log     *slog.Logger
	mu      sync.Mutex
	conn    *quic.Conn
	healthy atomic.Bool
	rtt     atomic.Int64
	lastErr atomic.Value
	open    atomic.Int64
}

func NewQUICClient(server, fingerprint, secret, sni string, log *slog.Logger) *QUICClient {
	cfg := certs.Pinned(fingerprint, PickSNI(sni, secret, ""))
	cfg.NextProtos = []string{"h3"} // like HTTP/3, not a name of pol's own
	q := &QUICClient{addr: server, tlsCfg: cfg, secret: secret, log: log}
	q.lastErr.Store("")
	return q
}

func (q *QUICClient) get(ctx context.Context) (*quic.Conn, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.conn != nil && q.conn.Context().Err() == nil {
		return q.conn, nil
	}
	ctx, cancel := context.WithTimeout(ctx, headerTimeout)
	defer cancel()
	start := time.Now()
	c, err := quic.DialAddr(ctx, q.addr, q.tlsCfg, quicConfig())
	if err != nil {
		err = fmt.Errorf("quic handshake with %s: %w", q.addr, err)
		q.failed(err)
		return nil, err
	}
	q.rtt.Store(int64(time.Since(start)))
	q.conn = c
	if !q.healthy.Swap(true) {
		q.log.Info("quic mode up")
	}
	q.lastErr.Store("")
	return c, nil
}

func (q *QUICClient) failed(err error) {
	if q.healthy.Swap(false) {
		q.log.Warn("quic mode down", "err", err)
	}
	q.lastErr.Store(err.Error())
}

func (q *QUICClient) drop(c *quic.Conn) {
	q.mu.Lock()
	if q.conn == c {
		q.conn = nil
	}
	q.mu.Unlock()
	_ = c.CloseWithError(0, "")
}

func (q *QUICClient) Dial(target string) (net.Conn, error) {
	var last error
	for range 2 {
		c, err := q.get(context.Background())
		if err != nil {
			// A handshake can be lost like any packet: try once more.
			last = err
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), headerTimeout)
		st, err := c.OpenStreamSync(ctx)
		cancel()
		if err != nil {
			last = fmt.Errorf("quic: opening a stream: %w", err)
			q.drop(c)
			continue
		}
		qs := &quicStream{Stream: st, conn: c}
		err = startLine(qs, "POL1 "+q.secret+" "+target, target)
		if err == nil {
			q.open.Add(1)
			return &countedConn{Conn: qs, done: func() { q.open.Add(-1) }}, nil
		}
		qs.Close()
		if errors.Is(err, ErrRejected) {
			return nil, err
		}
		last = fmt.Errorf("quic: first line: %w", err)
		q.drop(c)
	}
	q.failed(last)
	return nil, last
}

// Watch keeps the connection up until ctx ends, so it is ready (and its
// state known) before a user needs it.
func (q *QUICClient) Watch(ctx context.Context) {
	for {
		_, _ = q.get(ctx)
		select {
		case <-ctx.Done():
			q.mu.Lock()
			if q.conn != nil {
				_ = q.conn.CloseWithError(0, "")
				q.conn = nil
			}
			q.mu.Unlock()
			return
		case <-time.After(10 * time.Second):
		}
	}
}

func (q *QUICClient) Status() ModeStatus {
	return ModeStatus{Up: q.healthy.Load(), RTTms: float64(q.rtt.Load()) / 1e6, Open: q.open.Load(), Err: q.lastErr.Load().(string)}
}
