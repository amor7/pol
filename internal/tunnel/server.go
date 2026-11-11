// Package tunnel carries TCP connections (and UDP, as framed datagrams) from
// the relay to the server in several ways - the modes. Each mode is only a
// different road: at the end of every one the server reads which service
// the relay wants, checks it, connects, and copies both ways (endpoint.go).
package tunnel

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/ssh"
)

const (
	PathStream   = "/v1/s"
	PathPing     = "/v1/ping"
	PathSpeed    = "/v1/speed"
	PathWS       = "/v1/ws"
	HeaderTarget = "X-Pol-To"
)

// ALPN names. The one tunnel port tells the modes apart by these (and
// obfs by not being TLS at all).
const (
	ProtoRaw     = "pol1"   // tls mode and split subflows
	ProtoQUIC    = "pol-q1" // quic mode, on the same port number over UDP
	ProtoReverse = "pol-r1" // reverse mode, server to relay
)

// Window sizes. Go's defaults (1 MB for a whole connection) let one user
// who stops reading stall every other stream on the connection; these keep
// each stream's backlog to itself.
const (
	connWindow   = 256 << 20
	streamWindow = 4 << 20
)

// Server is the abroad end: it answers relays and connects their streams to
// the services they name.
type Server struct {
	Secret    string
	AnyTarget bool // allow targets other than this machine
	Log       *slog.Logger

	open, total  atomic.Int64
	up, down     atomic.Int64 // bytes from relays / to relays
	mu           sync.Mutex
	relays       map[string]*relaySeen
	srv          *http.Server
	dialer       net.Dialer
	refusedNoted atomic.Int64
	closed       atomic.Bool
	ln           net.Listener
	qln          *quic.Listener
	conns        map[net.Conn]struct{}
	splits       map[string]*splitPending
	links        map[string]*link
	replay       replayCache
	closers      []io.Closer

	// Camo is the real website camo mode borrows (its name, as relays
	// send it); CamoAddr where to reach it, host:443 if empty.
	Camo     string
	CamoAddr string
	// Next, when set, makes this server a middle hop: everything relays
	// ask for is passed on through Next, to the server behind it.
	Next    Dialer
	sshConf *ssh.ServerConfig
	xhttp   map[string]*xSession
}

// addCloser registers something Close must close; false if already closed.
func (s *Server) addCloser(c io.Closer) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return false
	}
	s.closers = append(s.closers, c)
	return true
}

type relaySeen struct {
	last time.Time
	open int64
}

func (s *Server) httpServer(cert tls.Certificate) *http.Server {
	p := new(http.Protocols)
	p.SetHTTP1(true) // ws mode, and the decoy page for browsers
	p.SetHTTP2(true)
	return &http.Server{
		Handler:   s,
		Protocols: p,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
		},
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams:          8192,
			MaxReceiveBufferPerConnection: connWindow,
			MaxReceiveBufferPerStream:     streamWindow,
			SendPingTimeout:               30 * time.Second,
			PingTimeout:                   15 * time.Second,
		},
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       3 * time.Minute,
		ErrorLog:          log.New(io.Discard, "", 0), // scanners' failed handshakes are not news
	}
}

// Serve answers on the TCP listener l until Close. What arrives is told
// apart by its first bytes: a TLS handshake (then ALPN picks mux, ws or
// tls/split), an HTTP request in the clear (the decoy), or anything else,
// which can only be obfs.
func (s *Server) Serve(l net.Listener, cert tls.Certificate) error {
	s.mu.Lock()
	s.srv = s.httpServer(cert)
	s.ln = l
	s.mu.Unlock()
	s.enableSSH(cert)
	tlsCfg := s.srv.TLSConfig.Clone()
	tlsCfg.NextProtos = []string{"h2", "http/1.1", ProtoRaw}
	httpL := newChanListener(l.Addr())
	go func() { _ = s.srv.Serve(httpL) }()
	for {
		c, err := l.Accept()
		if err != nil {
			httpL.Close()
			if s.closed.Load() {
				return http.ErrServerClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go s.first(c, tlsCfg, httpL)
	}
}

func (s *Server) first(c net.Conn, tlsCfg *tls.Config, httpL *chanListener) {
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	pc := &peekConn{Conn: c, br: bufio.NewReaderSize(c, 32<<10)}
	b, err := pc.br.Peek(1)
	if err != nil {
		c.Close()
		return
	}
	ip := hostOf(c.RemoteAddr())
	if b[0] == recHandsh && s.Camo != "" {
		// A ClientHello naming the borrowed site is camo mode's.
		if h, err := pc.br.Peek(5); err == nil {
			n := int(h[3])<<8 | int(h[4])
			if rec, err := pc.br.Peek(5 + n); err == nil && strings.EqualFold(helloSNI(rec), s.Camo) {
				s.serveCamo(c, pc.br, ip)
				return
			}
		}
	}
	if b[0] == 'S' {
		if v, err := pc.br.Peek(4); err == nil && string(v) == "SSH-" {
			s.serveSSH(pc, ip)
			return
		}
	}
	switch {
	case b[0] == 0x16: // TLS handshake record
		tc := tls.Server(pc, tlsCfg)
		_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
		if err := tc.Handshake(); err != nil {
			c.Close()
			return
		}
		_ = tc.SetDeadline(time.Time{})
		if tc.ConnectionState().NegotiatedProtocol == ProtoRaw {
			s.serveLine(tc, ip, rawPreambleWait, nil)
			return
		}
		if !httpL.push(tc) {
			tc.Close()
		}
	case b[0] >= 'A' && b[0] <= 'Z': // plain HTTP: someone looking around
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nServer: nginx\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html>\r\n<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>\r\n<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n<center>The plain HTTP request was sent to HTTPS port</center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n")
		c.Close()
	default:
		s.serveObfs(pc, ip)
	}
}

// Close stops answering and drops every stream.
func (s *Server) Close() error {
	s.closed.Store(true)
	s.mu.Lock()
	ln, qln, conns, links, closers, xs := s.ln, s.qln, s.conns, s.links, s.closers, s.xhttp
	s.conns, s.links, s.closers, s.xhttp = nil, nil, nil, nil
	s.mu.Unlock()
	for _, x := range xs {
		x.Close()
	}
	for _, c := range closers {
		c.Close()
	}
	if ln != nil {
		ln.Close()
	}
	if qln != nil {
		qln.Close()
	}
	for _, l := range links {
		l.stop()
	}
	for c := range conns {
		c.Close()
	}
	if s.srv == nil {
		return nil
	}
	return s.srv.Close()
}

// track remembers open stream connections so Close can end them.
func (s *Server) track(c net.Conn, add bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !add {
		delete(s.conns, c)
		return true
	}
	if s.closed.Load() {
		return false
	}
	if s.conns == nil {
		s.conns = map[net.Conn]struct{}{}
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "nginx")
	if !s.authorized(r) {
		decoy(w)
		return
	}
	if strings.HasPrefix(r.URL.Path, PathXHTTP) {
		s.serveXHTTP(w, r)
		return
	}
	switch r.URL.Path {
	case PathPing:
		s.seenIP(hostOfString(r.RemoteAddr), 0)
		w.WriteHeader(http.StatusNoContent)
	case PathStream:
		s.stream(w, r)
	case PathWS:
		s.serveWS(w, r)
	case PathSpeed:
		s.speed(w, r)
	default:
		decoy(w)
	}
}

func (s *Server) authorized(r *http.Request) bool {
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && s.secretOK(got)
}

func (s *Server) secretOK(got string) bool {
	return s.Secret != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.Secret)) == 1
}

// decoy is what anyone without the secret sees: an ordinary web server with
// nothing on it.
func decoy(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n")
}

// stream is the mux mode: one HTTP/2 request per connection.
func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != 2 || r.Method != http.MethodPost {
		http.Error(w, "HTTP/2 POST only", http.StatusBadRequest)
		return
	}
	ep, st := s.endpoint(r.Context(), r.Header.Get(HeaderTarget))
	if ep == nil {
		http.Error(w, statusText(st), httpStatus(st))
		return
	}
	defer ep.close()
	// A gone relay ends the request context; take the service side down too.
	stop := context.AfterFunc(r.Context(), ep.close)
	defer stop()

	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{}) // a stream lives as long as what it carries
	_ = rc.SetWriteDeadline(time.Time{})
	w.WriteHeader(http.StatusOK)
	if rc.Flush() != nil {
		return
	}
	ip := hostOfString(r.RemoteAddr)
	s.begin(ip)
	defer s.end(ip)
	ep.run(s, &h2Conn{w: w, rc: rc, body: r.Body}, r.Body)
}

// h2Conn is the mux stream's response side seen as a connection. A
// response cannot be half-closed; it ends when the handler returns.
type h2Conn struct {
	w    http.ResponseWriter
	rc   *http.ResponseController
	body io.Reader
}

func (c *h2Conn) Read(p []byte) (int, error) { return c.body.Read(p) }
func (c *h2Conn) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if err == nil {
		err = c.rc.Flush()
	}
	return n, err
}
func (c *h2Conn) CloseWrite() error                { return nil }
func (c *h2Conn) Close() error                     { return nil }
func (c *h2Conn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *h2Conn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *h2Conn) SetDeadline(time.Time) error      { return nil }
func (c *h2Conn) SetReadDeadline(time.Time) error  { return nil }
func (c *h2Conn) SetWriteDeadline(time.Time) error { return nil }

// speed is what relays before 1.3 used for `pol speedtest`; newer ones
// measure through each mode with the @down and @up targets.
func (s *Server) speed(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		n, _ := io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int64{"bytes": n})
		return
	}
	mb, _ := strconv.Atoi(r.URL.Query().Get("mb"))
	mb = max(1, min(mb, 200))
	w.Header().Set("Content-Length", strconv.Itoa(mb<<20))
	chunk := make([]byte, 64<<10)
	for i := 0; i < mb*16; i++ {
		if _, err := w.Write(chunk); err != nil {
			return
		}
	}
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func hostOf(a net.Addr) string { return hostOfString(a.String()) }

func hostOfString(s string) string {
	h, _, err := net.SplitHostPort(s)
	if err != nil {
		return s
	}
	return h
}

func (s *Server) begin(ip string) {
	s.open.Add(1)
	s.total.Add(1)
	s.seenIP(ip, 1)
}

func (s *Server) end(ip string) {
	s.open.Add(-1)
	s.seenIP(ip, -1)
}

func (s *Server) seenIP(ip string, delta int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.relays == nil {
		s.relays = map[string]*relaySeen{}
	}
	rs := s.relays[ip]
	if rs == nil {
		rs = &relaySeen{}
		s.relays[ip] = rs
		s.Log.Info("relay connected", "ip", ip)
	}
	rs.last = time.Now()
	rs.open += delta
}

// RelayStatus is one relay as the server last saw it.
type RelayStatus struct {
	IP       string `json:"ip"`
	LastSeen int64  `json:"last_seen"`
	Open     int64  `json:"open"`
}

// ServerStats is what `pol status` shows on the server.
type ServerStats struct {
	Open   int64         `json:"open"`
	Total  int64         `json:"total"`
	Up     int64         `json:"up"`
	Down   int64         `json:"down"`
	Relays []RelayStatus `json:"relays"`
	QUIC   bool          `json:"quic"`
	Links  []LinkStatus  `json:"links,omitempty"`
}

func (s *Server) Stats() ServerStats {
	st := ServerStats{Open: s.open.Load(), Total: s.total.Load(), Up: s.up.Load(), Down: s.down.Load(), Relays: []RelayStatus{}}
	s.mu.Lock()
	for ip, rs := range s.relays {
		// Relays ping every 15 seconds; one quiet for ten minutes is gone.
		if rs.open <= 0 && time.Since(rs.last) > 10*time.Minute {
			delete(s.relays, ip)
			continue
		}
		st.Relays = append(st.Relays, RelayStatus{IP: ip, LastSeen: rs.last.Unix(), Open: rs.open})
	}
	st.QUIC = s.qln != nil
	for _, l := range s.links {
		st.Links = append(st.Links, l.status())
	}
	s.mu.Unlock()
	sort.Slice(st.Relays, func(i, j int) bool { return st.Relays[i].IP < st.Relays[j].IP })
	sort.Slice(st.Links, func(i, j int) bool { return st.Links[i].Addr < st.Links[j].Addr })
	return st
}

// peekConn is a connection whose first bytes have been looked at.
type peekConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *peekConn) Read(p []byte) (int, error) { return c.br.Read(p) }
func (c *peekConn) CloseWrite() error          { return closeWrite(c.Conn) }
