package tunnel

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
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
)

// The ws mode: each connection is a WebSocket on the tunnel port, as a web
// page would open one. Because it is ordinary HTTP, it can also go through
// a CDN such as Cloudflare: then the relay talks to the CDN, the CDN talks
// to the server, and the server's own address can be blocked without the
// tunnel noticing. Inside, the line protocol runs as in the other modes.

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// serveWS upgrades an authorized request and serves the line protocol in it.
func (s *Server) serveWS(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || key == "" {
		decoy(w)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "HTTP/1.1 only", http.StatusBadRequest)
		return
	}
	c, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(brw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", wsAccept(key))
	if brw.Flush() != nil {
		c.Close()
		return
	}
	// Behind a CDN the connection comes from the CDN; it says who sent it.
	ip := r.Header.Get("CF-Connecting-IP")
	if ip == "" {
		ip = hostOfString(r.RemoteAddr)
	}
	s.serveLine(newWS(c, brw.Reader, false), ip, rawPreambleWait, nil)
}

// wsConn is a WebSocket as a byte stream: binary frames out, any data
// frames in. A close frame means "nothing more from me" - a half-close.
type wsConn struct {
	net.Conn
	br     *bufio.Reader
	client bool // clients mask what they send

	wmu    sync.Mutex
	rem    int64 // payload bytes left in the current frame
	masked bool
	mask   [4]byte
	mpos   int
	eof    bool
	closed atomic.Bool
	quit   chan struct{}
}

func newWS(c net.Conn, br *bufio.Reader, client bool) *wsConn {
	ws := &wsConn{Conn: c, br: br, client: client, quit: make(chan struct{})}
	go ws.keepalive()
	return ws
}

// keepalive pings every 30 seconds: CDNs drop WebSockets that are quiet for
// a minute or two, and a user's connection may well be.
func (c *wsConn) keepalive() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.quit:
			return
		case <-t.C:
			if c.frame(0x9, nil) != nil {
				return
			}
		}
	}
}

func (c *wsConn) Read(p []byte) (int, error) {
	for c.rem == 0 {
		if c.eof {
			return 0, io.EOF
		}
		var h [2]byte
		if _, err := io.ReadFull(c.br, h[:]); err != nil {
			return 0, err
		}
		op := h[0] & 0x0f
		c.masked = h[1]&0x80 != 0
		n := int64(h[1] & 0x7f)
		switch n {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(c.br, b[:]); err != nil {
				return 0, err
			}
			n = int64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(c.br, b[:]); err != nil {
				return 0, err
			}
			n = int64(binary.BigEndian.Uint64(b[:]))
		}
		if c.masked {
			if _, err := io.ReadFull(c.br, c.mask[:]); err != nil {
				return 0, err
			}
			c.mpos = 0
		}
		switch op {
		case 0x0, 0x1, 0x2: // data
			c.rem = n
		case 0x8: // close: the peer has finished sending
			_, _ = io.CopyN(io.Discard, c.br, n)
			c.eof = true
		case 0x9: // ping
			b := make([]byte, n)
			if _, err := io.ReadFull(c.br, b); err != nil {
				return 0, err
			}
			c.unmask(b)
			_ = c.frame(0xA, b)
		default: // pong and anything else
			if _, err := io.CopyN(io.Discard, c.br, n); err != nil {
				return 0, err
			}
		}
	}
	if int64(len(p)) > c.rem {
		p = p[:c.rem]
	}
	n, err := c.br.Read(p)
	c.unmask(p[:n])
	c.rem -= int64(n)
	return n, err
}

func (c *wsConn) unmask(b []byte) {
	if !c.masked {
		return
	}
	for i := range b {
		b[i] ^= c.mask[c.mpos&3]
		c.mpos++
	}
}

// frame writes one frame with the given opcode.
func (c *wsConn) frame(op byte, p []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	h := make([]byte, 0, 14+len(p))
	h = append(h, 0x80|op)
	mbit := byte(0)
	if c.client {
		mbit = 0x80
	}
	switch n := len(p); {
	case n < 126:
		h = append(h, mbit|byte(n))
	case n < 1<<16:
		h = append(h, mbit|126, byte(n>>8), byte(n))
	default:
		h = append(h, mbit|127)
		h = binary.BigEndian.AppendUint64(h, uint64(n))
	}
	if c.client {
		var m [4]byte
		_, _ = rand.Read(m[:])
		h = append(h, m[:]...)
		start := len(h)
		h = append(h, p...)
		for i := range p {
			h[start+i] ^= m[i&3]
		}
	} else {
		h = append(h, p...)
	}
	_, err := c.Conn.Write(h)
	return err
}

func (c *wsConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), 32<<10)
		if err := c.frame(0x2, p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (c *wsConn) CloseWrite() error { return c.frame(0x8, nil) }

func (c *wsConn) Close() error {
	if !c.closed.Swap(true) {
		close(c.quit)
	}
	return c.Conn.Close()
}

// WSConfig says where the ws mode connects.
type WSConfig struct {
	Server      string // the tunnel's host:port, used without a CDN
	Fingerprint string
	SNI         string
	// CDN, when set, is the domain the CDN serves the server under; the
	// relay then connects to CDNAddr (or the domain) on CDNPort and trusts
	// the CDN's ordinary certificate.
	CDN     string
	CDNAddr string
	CDNPort int
}

// NewWSClient is the ws mode's relay side.
func NewWSClient(cfg WSConfig, secret string, warm int, log *slog.Logger) *LineDialer {
	d := newLineDialer("ws", secret, warm, log, wsConnect(cfg, secret))
	return d
}

func wsConnect(cfg WSConfig, secret string) func(context.Context) (net.Conn, error) {
	var tlsCfg *tls.Config
	addr, host := cfg.Server, PickSNI(cfg.SNI, secret, "")
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
		tlsCfg.NextProtos = []string{"http/1.1"}
	}
	return func(ctx context.Context) (net.Conn, error) {
		var c net.Conn
		var err error
		if tlsCfg != nil { // through the CDN, which shows its own certificate
			d := tls.Dialer{NetDialer: &net.Dialer{KeepAlive: 30 * time.Second}, Config: tlsCfg}
			c, err = d.DialContext(ctx, "tcp", addr)
		} else { // Chrome opens a WebSocket's connection offering only http/1.1
			c, err = chromeDial(ctx, addr, host, cfg.Fingerprint, []string{"http/1.1"})
		}
		if err != nil {
			return nil, err
		}
		if dl, ok := ctx.Deadline(); ok {
			_ = c.SetDeadline(dl)
		}
		k := make([]byte, 16)
		_, _ = rand.Read(k)
		key := base64.StdEncoding.EncodeToString(k)
		_, err = fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer %s\r\n\r\n", PathWS, host, key, secret)
		if err != nil {
			c.Close()
			return nil, err
		}
		br := bufio.NewReaderSize(c, 32<<10)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			c.Close()
			return nil, err
		}
		if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("Sec-WebSocket-Accept") != wsAccept(key) {
			c.Close()
			if resp.StatusCode == http.StatusNotFound {
				return nil, errors.New("the server did not accept the WebSocket - is the token current, and does the CDN point at the tunnel port?")
			}
			return nil, fmt.Errorf("the server answered %s instead of upgrading to WebSocket", resp.Status)
		}
		_ = c.SetDeadline(time.Time{})
		return newWS(c, br, true), nil
	}
}
