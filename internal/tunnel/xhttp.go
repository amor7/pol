package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amor7/pol/internal/certs"
)

// The xhttp mode: plain HTTP requests, the way a web page fetches things.
// The data coming down arrives on one long GET; the data going up is sent
// as POSTs, each a numbered chunk, which the server puts back in order. No
// WebSocket and no unusual headers, so it passes CDNs and proxies that only
// carry ordinary requests. Inside, the line protocol runs as in the other
// modes.
//
// Down, the GET's body is frames of  length (4) | data ; a frame of length
// zero is a keepalive, sent when nothing else has been for a while, because
// CDNs end responses that stay silent too long.

const PathXHTTP = "/v1/x/"

const (
	xhttpChunk     = 256 << 10 // most data in one POST
	xhttpInflight  = 4         // POSTs in flight at once
	xhttpGather    = 2 * time.Millisecond
	xhttpKeepalive = 20 * time.Second
	xhttpHeld      = 32 << 20 // most out-of-order upload data held
)

// ---------------------------------------------------------------- server

type xSession struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    map[uint64][]byte
	held   int
	next   uint64
	finSeq int64
	cur    []byte
	closed bool

	wmu  sync.Mutex
	w    http.ResponseWriter
	rc   *http.ResponseController
	last atomic.Int64 // unix nano of the last frame down
	done chan struct{}
	once sync.Once
}

func (x *xSession) push(seq uint64, data []byte, fin bool) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	for x.held > xhttpHeld && seq != x.next && !x.closed {
		x.cond.Wait()
	}
	if x.closed || seq < x.next {
		return !x.closed
	}
	if fin {
		x.finSeq = int64(seq)
	} else {
		x.buf[seq] = data
		x.held += len(data)
	}
	x.cond.Broadcast()
	return true
}

func (x *xSession) Read(p []byte) (int, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	for {
		if len(x.cur) > 0 {
			n := copy(p, x.cur)
			x.cur = x.cur[n:]
			return n, nil
		}
		if d, ok := x.buf[x.next]; ok {
			delete(x.buf, x.next)
			x.held -= len(d)
			x.next++
			x.cur = d
			x.cond.Broadcast()
			continue
		}
		if x.finSeq >= 0 && x.next == uint64(x.finSeq) {
			return 0, io.EOF
		}
		if x.closed {
			return 0, net.ErrClosed
		}
		x.cond.Wait()
	}
}

func (x *xSession) frame(p []byte) error {
	x.wmu.Lock()
	defer x.wmu.Unlock()
	select {
	case <-x.done:
		return net.ErrClosed
	default:
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(p)))
	if _, err := x.w.Write(h[:]); err != nil {
		return err
	}
	if len(p) > 0 {
		if _, err := x.w.Write(p); err != nil {
			return err
		}
	}
	x.last.Store(time.Now().UnixNano())
	return x.rc.Flush()
}

func (x *xSession) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), 32<<10)
		if err := x.frame(p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// CloseWrite ends the GET: the handler returns once the stream is served.
func (x *xSession) CloseWrite() error { return nil }

func (x *xSession) Close() error {
	x.once.Do(func() {
		x.mu.Lock()
		x.closed = true
		x.cond.Broadcast()
		x.mu.Unlock()
		close(x.done)
	})
	return nil
}

func (x *xSession) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (x *xSession) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (x *xSession) SetDeadline(time.Time) error      { return nil }
func (x *xSession) SetReadDeadline(time.Time) error  { return nil }
func (x *xSession) SetWriteDeadline(time.Time) error { return nil }

func (s *Server) xsession(id string) *xSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.xhttp[id]
}

// serveXHTTP answers /v1/x/<id> (GET: the session's way down) and
// /v1/x/<id>/<seq> (POST: one chunk up; ?fin=1 marks the end).
func (s *Server) serveXHTTP(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, PathXHTTP)
	id, seqStr, isPost := strings.Cut(rest, "/")
	if len(id) != 32 {
		decoy(w)
		return
	}
	if !isPost {
		if r.Method != http.MethodGet {
			decoy(w)
			return
		}
		s.xhttpDown(w, r, id)
		return
	}
	seq, err := strconv.ParseUint(seqStr, 10, 64)
	if err != nil || r.Method != http.MethodPost {
		decoy(w)
		return
	}
	x := s.xsession(id)
	if x == nil {
		http.Error(w, "no such session", http.StatusNotFound)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, xhttpChunk+1))
	if err != nil || len(data) > xhttpChunk {
		http.Error(w, "bad chunk", http.StatusBadRequest)
		return
	}
	if !x.push(seq, data, r.URL.Query().Get("fin") == "1") {
		http.Error(w, "session closed", http.StatusGone)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) xhttpDown(w http.ResponseWriter, r *http.Request, id string) {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	x := &xSession{buf: map[uint64][]byte{}, finSeq: -1, w: w, rc: rc, done: make(chan struct{})}
	x.cond = sync.NewCond(&x.mu)
	s.mu.Lock()
	if s.xhttp == nil {
		s.xhttp = map[string]*xSession{}
	}
	if s.closed.Load() || s.xhttp[id] != nil {
		s.mu.Unlock()
		http.Error(w, "busy", http.StatusConflict)
		return
	}
	s.xhttp[id] = x
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.xhttp, id)
		s.mu.Unlock()
		x.Close()
	}()

	// Headers that keep CDNs and proxies from buffering or caching.
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache, no-store, no-transform")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if rc.Flush() != nil {
		return
	}
	x.last.Store(time.Now().UnixNano())
	stop := context.AfterFunc(r.Context(), func() { x.Close() })
	defer stop()
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-x.done:
				return
			case <-t.C:
				if time.Since(time.Unix(0, x.last.Load())) >= xhttpKeepalive {
					_ = x.frame(nil)
				}
			}
		}
	}()
	ip := r.Header.Get("CF-Connecting-IP")
	if ip == "" {
		ip = hostOfString(r.RemoteAddr)
	}
	s.serveLine(x, ip, rawPreambleWait, nil)
}

// ---------------------------------------------------------------- relay

// xConn is the relay's end of one xhttp session.
type xConn struct {
	c      *http.Client
	base   string
	host   string
	secret string
	ctx    context.Context
	cancel context.CancelFunc
	body   io.ReadCloser
	rcur   []byte

	mu     sync.Mutex
	cond   *sync.Cond
	out    []byte
	fin    bool
	err    error
	seq    uint64
	flight int
	closed bool
	idle   chan struct{} // closed when the sender has sent everything, fin included
}

func (x *xConn) req(method, path string, body []byte) *http.Request {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	r, _ := http.NewRequestWithContext(x.ctx, method, x.base+path, rd)
	if x.host != "" {
		r.Host = x.host
	}
	r.Header.Set("Authorization", "Bearer "+x.secret)
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	return r
}

func (x *xConn) Read(p []byte) (int, error) {
	for len(x.rcur) == 0 {
		var h [4]byte
		if _, err := io.ReadFull(x.body, h[:]); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, io.EOF
			}
			return 0, err
		}
		n := binary.BigEndian.Uint32(h[:])
		if n > 1<<20 {
			return 0, errors.New("xhttp: oversized frame")
		}
		if n == 0 {
			continue // keepalive
		}
		x.rcur = make([]byte, n)
		if _, err := io.ReadFull(x.body, x.rcur); err != nil {
			return 0, err
		}
	}
	n := copy(p, x.rcur)
	x.rcur = x.rcur[n:]
	return n, nil
}

func (x *xConn) Write(p []byte) (int, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.err != nil {
		return 0, x.err
	}
	if x.closed || x.fin {
		return 0, net.ErrClosed
	}
	// Hold the writer back when far ahead of what has been sent.
	for len(x.out) > 4*xhttpChunk && x.err == nil && !x.closed {
		x.cond.Wait()
	}
	x.out = append(x.out, p...)
	x.cond.Broadcast()
	return len(p), x.err
}

// sender turns what was written into POSTs, a few in flight at once.
func (x *xConn) sender() {
	defer close(x.idle)
	for {
		x.mu.Lock()
		for len(x.out) == 0 && !x.fin && !x.closed && x.err == nil {
			x.cond.Wait()
		}
		if x.closed || x.err != nil {
			x.mu.Unlock()
			return
		}
		x.mu.Unlock()
		time.Sleep(xhttpGather) // let a burst of small writes arrive together
		x.mu.Lock()
		for x.flight >= xhttpInflight && x.err == nil && !x.closed {
			x.cond.Wait()
		}
		if x.closed || x.err != nil {
			x.mu.Unlock()
			return
		}
		var chunk []byte
		last := false
		if len(x.out) > 0 {
			n := min(len(x.out), xhttpChunk)
			chunk = append([]byte(nil), x.out[:n]...)
			x.out = x.out[n:]
		} else if x.fin {
			last = true
		}
		seq := x.seq
		x.seq++
		x.flight++
		x.cond.Broadcast()
		x.mu.Unlock()

		go func() {
			path := "/" + strconv.FormatUint(seq, 10)
			if last {
				path += "?fin=1"
			}
			err := x.post(path, chunk)
			x.mu.Lock()
			x.flight--
			if err != nil && x.err == nil {
				x.err = err
			}
			x.cond.Broadcast()
			x.mu.Unlock()
		}()
		if last {
			x.mu.Lock()
			for x.flight > 0 && x.err == nil && !x.closed {
				x.cond.Wait()
			}
			x.mu.Unlock()
			return
		}
	}
}

func (x *xConn) post(suffix string, body []byte) error {
	if body == nil {
		body = []byte{}
	}
	resp, err := x.c.Do(x.req(http.MethodPost, suffix, body))
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("xhttp: upload answered %s", resp.Status)
	}
	return nil
}

// CloseWrite sends what is left and then the end of the upload.
func (x *xConn) CloseWrite() error {
	x.mu.Lock()
	if x.fin || x.closed {
		x.mu.Unlock()
		return nil
	}
	x.fin = true
	x.cond.Broadcast()
	x.mu.Unlock()
	select {
	case <-x.idle:
	case <-x.ctx.Done():
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.err
}

func (x *xConn) Close() error {
	x.mu.Lock()
	x.closed = true
	x.cond.Broadcast()
	x.mu.Unlock()
	x.cancel()
	return x.body.Close()
}

func (x *xConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (x *xConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (x *xConn) SetDeadline(time.Time) error      { return nil }
func (x *xConn) SetReadDeadline(time.Time) error  { return nil }
func (x *xConn) SetWriteDeadline(time.Time) error { return nil }

// NewXHTTPClient is the xhttp mode's relay side; cfg is where it connects,
// as for ws (straight to the server, or through a CDN).
func NewXHTTPClient(cfg WSConfig, secret string, warm int, log *slog.Logger) *LineDialer {
	addr, host := cfg.Server, cfg.SNI
	if host == "" {
		host = "example.com"
	}
	var tlsCfg *tls.Config
	if cfg.CDN != "" {
		host = cfg.CDN
		a := cfg.CDNAddr
		if a == "" {
			a = cfg.CDN
		}
		port := cfg.CDNPort
		if port == 0 {
			port = 443
		}
		addr = net.JoinHostPort(a, strconv.Itoa(port))
		tlsCfg = &tls.Config{ServerName: cfg.CDN, MinVersion: tls.VersionTLS12}
	} else {
		tlsCfg = certs.Pinned(cfg.Fingerprint, host)
	}
	tr := &http.Transport{
		TLSClientConfig:     tlsCfg,
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
			return d.DialContext(ctx, "tcp", addr)
		},
		HTTP2: &http.HTTP2Config{MaxReceiveBufferPerConnection: connWindow, MaxReceiveBufferPerStream: streamWindow},
	}
	hc := &http.Client{Transport: tr}
	base := "https://" + host
	if _, p, _ := net.SplitHostPort(addr); p != "443" {
		base = "https://" + net.JoinHostPort(host, p)
	}
	return newLineDialer("xhttp", secret, warm, log, func(ctx context.Context) (net.Conn, error) {
		idb := make([]byte, 16)
		_, _ = rand.Read(idb)
		id := hex.EncodeToString(idb)
		xctx, cancel := context.WithCancel(context.Background())
		x := &xConn{c: hc, base: base + PathXHTTP + id, host: host, secret: secret, ctx: xctx, cancel: cancel, idle: make(chan struct{})}
		x.cond = sync.NewCond(&x.mu)
		// The way down first: uploads need the session it creates.
		req := x.req(http.MethodGet, "", nil)
		timer := time.AfterFunc(headerTimeout, cancel)
		stop := context.AfterFunc(ctx, cancel)
		resp, err := hc.Do(req)
		stop()
		if !timer.Stop() && err == nil {
			resp.Body.Close()
			err = errors.New("xhttp: no answer in time")
		}
		if err != nil {
			cancel()
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			cancel()
			if resp.StatusCode == http.StatusNotFound {
				return nil, errors.New("the server did not accept xhttp - is the token current, and is the server running a current pol?")
			}
			return nil, fmt.Errorf("xhttp: the server answered %s", resp.Status)
		}
		x.body = resp.Body
		go x.sender()
		return x, nil
	})
}
