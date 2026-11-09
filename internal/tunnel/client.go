package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amor7/pol/internal/certs"
)

// headerTimeout bounds how long a new stream may wait for the server to say
// it reached the service. The stream itself may then live for days.
const headerTimeout = 12 * time.Second

// ErrRejected marks an answer from a healthy server that refused one
// stream (wrong port, nothing listening): the connection itself is fine.
var ErrRejected = errors.New("rejected by the server")

// Client is the relay end: a few HTTP/2 connections to the server, each
// carrying many streams. New streams go to the least busy healthy one.
type Client struct {
	base   string
	secret string
	pool   []*member
	log    *slog.Logger
	next   atomic.Uint32
}

type member struct {
	http    *http.Client
	tr      *http.Transport
	open    atomic.Int64
	healthy atomic.Bool
	rtt     atomic.Int64 // nanoseconds, last ping
	lastErr atomic.Value // string
}

// NewClient prepares n connections to server (host:port). Nothing is dialled
// until the first stream or ping.
func NewClient(server, fingerprint, secret, sni string, n int, log *slog.Logger) *Client {
	if sni == "" {
		sni = "example.com"
	}
	c := &Client{base: "https://" + server, secret: secret, log: log}
	for range max(1, n) {
		p := new(http.Protocols)
		p.SetHTTP2(true)
		tr := &http.Transport{
			TLSClientConfig:     certs.Pinned(fingerprint, sni),
			Protocols:           p,
			ForceAttemptHTTP2:   true,
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			HTTP2: &http.HTTP2Config{
				MaxReceiveBufferPerConnection: connWindow,
				MaxReceiveBufferPerStream:     streamWindow,
				SendPingTimeout:               20 * time.Second,
				PingTimeout:                   10 * time.Second,
			},
		}
		m := &member{http: &http.Client{Transport: tr}, tr: tr}
		m.lastErr.Store("")
		c.pool = append(c.pool, m)
	}
	return c
}

// Close drops every connection.
func (c *Client) Close() {
	for _, m := range c.pool {
		m.tr.CloseIdleConnections()
	}
}

func (c *Client) pick() *member {
	var best *member
	for _, m := range c.pool {
		if !m.healthy.Load() {
			continue
		}
		if best == nil || m.open.Load() < best.open.Load() {
			best = m
		}
	}
	if best == nil {
		// None known healthy (just started, or all failing): rotate, so a
		// connection that has recovered is found by the next stream.
		best = c.pool[int(c.next.Add(1))%len(c.pool)]
	}
	return best
}

// Dial opens a stream to target (host:port as the server sees it).
func (c *Client) Dial(target string) (net.Conn, error) {
	m := c.pick()
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.base+PathStream, pr)
	req.Header.Set("Authorization", "Bearer "+c.secret)
	req.Header.Set(HeaderTarget, target)
	req.ContentLength = -1

	timer := time.AfterFunc(headerTimeout, cancel)
	resp, err := m.http.Do(req)
	inTime := timer.Stop()
	if err != nil || !inTime {
		cancel()
		pw.Close()
		if err == nil {
			resp.Body.Close()
			err = errors.New("the server did not answer in time")
		}
		c.failed(m, err)
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		resp.Body.Close()
		cancel()
		pw.Close()
		if resp.StatusCode == http.StatusNotFound {
			err := errors.New("the server does not accept this relay's secret - get a new token with `pol token` on the server")
			c.failed(m, err)
			return nil, err
		}
		return nil, fmt.Errorf("%w: %s", ErrRejected, trimMsg(msg, resp.Status))
	}
	c.ok(m)
	m.open.Add(1)
	return &streamConn{body: resp.Body, pw: pw, cancel: cancel, done: func() { m.open.Add(-1) }}, nil
}

func trimMsg(b []byte, status string) string {
	s := string(b)
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	if s == "" {
		return status
	}
	return s
}

func (c *Client) ok(m *member) {
	if !m.healthy.Swap(true) {
		c.log.Info("tunnel connection up", "conn", c.index(m))
	}
	m.lastErr.Store("")
}

func (c *Client) failed(m *member, err error) {
	if m.healthy.Swap(false) {
		c.log.Warn("tunnel connection down", "conn", c.index(m), "err", err)
	}
	m.lastErr.Store(err.Error())
	// Throw the broken connection away so the next try dials afresh.
	m.tr.CloseIdleConnections()
}

func (c *Client) index(m *member) int {
	for i, x := range c.pool {
		if x == m {
			return i + 1
		}
	}
	return 0
}

// Ping asks one connection a trivial question and times it.
func (c *Client) Ping(ctx context.Context) (time.Duration, error) {
	return c.ping(ctx, c.pick())
}

func (c *Client) ping(ctx context.Context, m *member) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, headerTimeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.base+PathPing, nil)
	req.Header.Set("Authorization", "Bearer "+c.secret)
	start := time.Now()
	resp, err := m.http.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return time.Since(start), nil
	case http.StatusNotFound:
		return 0, errors.New("the server does not accept this relay's secret - get a new token with `pol token` on the server")
	default:
		return 0, fmt.Errorf("the server answered %s", resp.Status)
	}
}

// Watch pings every connection every 15 seconds until ctx ends, so a broken
// path is noticed (and redialled) before a user needs it.
func (c *Client) Watch(ctx context.Context) {
	check := func() {
		var wg sync.WaitGroup
		for _, m := range c.pool {
			wg.Add(1)
			go func() {
				defer wg.Done()
				d, err := c.ping(ctx, m)
				if err != nil {
					if ctx.Err() == nil {
						c.failed(m, err)
					}
					return
				}
				m.rtt.Store(int64(d))
				c.ok(m)
			}()
		}
		wg.Wait()
	}
	check()
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}

// ConnStatus is one tunnel connection as `pol status` shows it.
type ConnStatus struct {
	Up    bool    `json:"up"`
	RTTms float64 `json:"rtt_ms"`
	Open  int64   `json:"open"`
	Err   string  `json:"err,omitempty"`
}

func (c *Client) Status() []ConnStatus {
	out := make([]ConnStatus, len(c.pool))
	for i, m := range c.pool {
		out[i] = ConnStatus{Up: m.healthy.Load(), RTTms: float64(m.rtt.Load()) / 1e6, Open: m.open.Load(), Err: m.lastErr.Load().(string)}
	}
	return out
}

// SpeedDown fetches mb megabytes through the tunnel and returns the bytes.
func (c *Client) SpeedDown(ctx context.Context, mb int) (int64, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.base+PathSpeed+"?mb="+strconv.Itoa(mb), nil)
	req.Header.Set("Authorization", "Bearer "+c.secret)
	resp, err := c.pick().http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return io.Copy(io.Discard, resp.Body)
}

// SpeedUp sends mb megabytes through the tunnel and returns what arrived.
func (c *Client) SpeedUp(ctx context.Context, mb int) (int64, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.base+PathSpeed, io.LimitReader(zeros{}, int64(mb)<<20))
	req.Header.Set("Authorization", "Bearer "+c.secret)
	req.ContentLength = int64(mb) << 20
	resp, err := c.pick().http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	var got struct{ Bytes int64 }
	err = json.NewDecoder(resp.Body).Decode(&got)
	return got.Bytes, err
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// streamConn is one stream seen as a net.Conn.
type streamConn struct {
	body   io.ReadCloser
	pw     *io.PipeWriter
	cancel context.CancelFunc
	done   func()
	closed atomic.Bool
}

func (s *streamConn) Read(p []byte) (int, error)  { return s.body.Read(p) }
func (s *streamConn) Write(p []byte) (int, error) { return s.pw.Write(p) }

// CloseWrite tells the service the user has finished sending.
func (s *streamConn) CloseWrite() error { return s.pw.Close() }

func (s *streamConn) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	s.pw.Close()
	s.body.Close()
	s.cancel()
	s.done()
	return nil
}

func (s *streamConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (s *streamConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (s *streamConn) SetDeadline(time.Time) error      { return nil }
func (s *streamConn) SetReadDeadline(time.Time) error  { return nil }
func (s *streamConn) SetWriteDeadline(time.Time) error { return nil }
