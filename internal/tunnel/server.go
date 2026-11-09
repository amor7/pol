// Package tunnel carries TCP connections as streams inside HTTP/2
// connections over TLS: the relay opens a request per connection, the
// request body is what the user sends and the response body what comes
// back. From outside it is an HTTPS client talking to an HTTPS server.
package tunnel

import (
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
)

const (
	PathStream   = "/v1/s"
	PathPing     = "/v1/ping"
	PathSpeed    = "/v1/speed"
	HeaderTarget = "X-Pol-To"
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
	httpL        *chanListener
	raws         map[net.Conn]struct{}
}

type relaySeen struct {
	last time.Time
	open int64
}

// Serve answers on l until Close.
func (s *Server) Serve(l net.Listener, cert tls.Certificate) error {
	p := new(http.Protocols)
	p.SetHTTP1(true) // so a browser that wanders in gets the decoy page
	p.SetHTTP2(true)
	s.srv = &http.Server{
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
	// The TLS handshake is done here rather than by the HTTP server, so the
	// relay's ALPN can pick the mode: "h2" goes to the HTTP/2 tunnel,
	// ProtoRaw to one-connection-per-stream. Both share the one port.
	tlsCfg := s.srv.TLSConfig.Clone()
	tlsCfg.NextProtos = []string{"h2", "http/1.1", ProtoRaw}
	httpL := newChanListener(l.Addr())
	s.mu.Lock()
	s.ln, s.httpL = l, httpL
	s.mu.Unlock()
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
		go func() {
			tc := tls.Server(c, tlsCfg)
			_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
			if err := tc.Handshake(); err != nil {
				c.Close()
				return
			}
			_ = tc.SetDeadline(time.Time{})
			if tc.ConnectionState().NegotiatedProtocol == ProtoRaw {
				s.raw(tc)
				return
			}
			if !httpL.push(tc) {
				tc.Close()
			}
		}()
	}
}

// Close stops answering and drops every stream.
func (s *Server) Close() error {
	s.closed.Store(true)
	s.mu.Lock()
	ln, raws := s.ln, s.raws
	s.raws = nil
	s.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	for c := range raws {
		c.Close()
	}
	if s.srv == nil {
		return nil
	}
	return s.srv.Close()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "nginx")
	if !s.authorized(r) {
		decoy(w)
		return
	}
	switch r.URL.Path {
	case PathPing:
		s.seen(r, 0)
		w.WriteHeader(http.StatusNoContent)
	case PathStream:
		s.stream(w, r)
	case PathSpeed:
		s.speed(w, r)
	default:
		decoy(w)
	}
}

func (s *Server) authorized(r *http.Request) bool {
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && s.Secret != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.Secret)) == 1
}

// decoy is what anyone without the secret sees: an ordinary web server with
// nothing on it.
func decoy(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n")
}

func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != 2 || r.Method != http.MethodPost {
		http.Error(w, "HTTP/2 POST only", http.StatusBadRequest)
		return
	}
	target := r.Header.Get(HeaderTarget)
	up, code, msg := s.dialTarget(r.Context(), target)
	if up == nil {
		http.Error(w, msg, code)
		return
	}
	defer up.Close()
	// A gone relay ends the request context; take the service side down too.
	stop := context.AfterFunc(r.Context(), func() { up.Close() })
	defer stop()

	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{}) // a stream lives as long as what it carries
	_ = rc.SetWriteDeadline(time.Time{})
	w.WriteHeader(http.StatusOK)
	if rc.Flush() != nil {
		return
	}
	s.open.Add(1)
	s.total.Add(1)
	s.seen(r, 1)
	defer func() {
		s.open.Add(-1)
		s.seen(r, -1)
	}()

	go func() {
		n, _ := io.Copy(up, r.Body)
		s.up.Add(n)
		if cw, ok := up.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	buf := make([]byte, 32<<10)
	for {
		n, err := up.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			s.down.Add(int64(n))
			if rc.Flush() != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// speed sends (GET ?mb=N) or swallows (POST) data for `pol speedtest`.
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

// dialTarget checks and connects to what a relay asked for. On failure it
// returns the HTTP status and a message for the relay.
func (s *Server) dialTarget(ctx context.Context, target string) (net.Conn, int, string) {
	host, port, err := net.SplitHostPort(target)
	if n, perr := strconv.Atoi(port); err != nil || perr != nil || n < 1 || n > 65535 {
		return nil, http.StatusBadRequest, "bad target"
	}
	if !s.AnyTarget && !loopback(host) {
		if time.Now().Unix()-s.refusedNoted.Swap(time.Now().Unix()) > 60 {
			s.Log.Warn("refused a target on another machine; set any_target in the config to allow it", "target", target)
		}
		return nil, http.StatusForbidden, "only this machine's ports may be reached"
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	up, err := s.dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, http.StatusBadGateway, "nothing answers on " + target
	}
	return up, 0, ""
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) seen(r *http.Request, delta int64) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	s.seenIP(ip, delta)
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
	s.mu.Unlock()
	sort.Slice(st.Relays, func(i, j int) bool { return st.Relays[i].IP < st.Relays[j].IP })
	return st
}
