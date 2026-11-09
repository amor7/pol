package tunnel

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/amor7/pol/internal/certs"
)

// The reverse mode: the server abroad connects to the relay, not the other
// way round, and keeps a few connections waiting there. When a user
// arrives the relay takes one, sends the line protocol's first line on it,
// and the server serves it as if the relay had dialled. Useful where
// connections from Iran out to the server are cut but ones coming in are
// left alone.
//
// The relay listens with its own certificate, which the server pins; the
// server proves itself with the secret ("POL1R <secret>\n"), and the relay
// answers one byte.

const (
	reverseIdle   = 50 * time.Second // the server replaces a waiting connection after this
	reverseMaxAge = 40 * time.Second // the relay uses waiting connections younger than this
	reverseWarm   = 8
)

// ---------------------------------------------------------------- relay side

// ReverseListener is the relay's end: it accepts the server's connections
// and hands them out to users.
type ReverseListener struct {
	secret string
	log    *slog.Logger
	ln     net.Listener
	pool   chan pooled
	last   atomic.Int64 // when the server last connected
	open   atomic.Int64
	closed atomic.Bool
}

// ListenReverse starts listening on addr for the server.
func ListenReverse(addr string, cert tls.Certificate, secret string, log *slog.Logger) (*ReverseListener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	r := &ReverseListener{secret: secret, log: log, ln: ln, pool: make(chan pooled, 256)}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{ProtoReverse}, MinVersion: tls.VersionTLS13}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if r.closed.Load() {
					return
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			go r.accept(tls.Server(c, cfg))
		}
	}()
	return r, nil
}

// Addr is where the listener is.
func (r *ReverseListener) Addr() net.Addr { return r.ln.Addr() }

func (r *ReverseListener) accept(c *tls.Conn) {
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	if err := c.Handshake(); err != nil || c.ConnectionState().NegotiatedProtocol != ProtoReverse {
		c.Close()
		return
	}
	br := bufio.NewReaderSize(c, 4096)
	line, err := br.ReadString('\n')
	f := strings.Fields(line)
	if err != nil || len(f) != 2 || f[0] != "POL1R" || subtle.ConstantTimeCompare([]byte(f[1]), []byte(r.secret)) != 1 {
		c.Close()
		return
	}
	if _, err := c.Write([]byte{statusOK}); err != nil {
		c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	if r.last.Swap(time.Now().Unix()) == 0 {
		r.log.Info("reverse mode up: the server connected")
	}
	select {
	case r.pool <- pooled{&lineConn{Conn: c, br: br}, time.Now()}:
	default:
		c.Close()
	}
}

// Dial opens a stream to target over one of the server's waiting
// connections, waiting a few seconds for one if none is there.
func (r *ReverseListener) Dial(target string) (net.Conn, error) {
	deadline := time.After(8 * time.Second)
	for {
		var p pooled
		select {
		case p = <-r.pool:
		case <-deadline:
			return nil, errors.New("no connection from the server - run `pol link` on the server (see `pol reverse`)")
		}
		if time.Since(p.at) > reverseMaxAge {
			p.c.Close()
			continue
		}
		err := startLine(p.c, "POL1 "+r.secret+" "+target, target)
		if err == nil {
			r.open.Add(1)
			return &countedConn{Conn: p.c, done: func() { r.open.Add(-1) }}, nil
		}
		p.c.Close()
		if errors.Is(err, ErrRejected) {
			return nil, err
		}
	}
}

func (r *ReverseListener) Close() error {
	r.closed.Store(true)
	err := r.ln.Close()
	for {
		select {
		case p := <-r.pool:
			p.c.Close()
		default:
			return err
		}
	}
}

func (r *ReverseListener) Status() ModeStatus {
	last := r.last.Load()
	st := ModeStatus{Up: last != 0 && time.Now().Unix()-last < 90, Open: r.open.Load(), Ready: len(r.pool), Note: "listening on " + r.ln.Addr().String()}
	if !st.Up {
		st.Err = "the server has not connected - run `pol link` on it"
	}
	return st
}

// ---------------------------------------------------------------- server side

// Link is a relay the server keeps reverse connections open to.
type Link struct {
	Addr        string `json:"addr"`
	Fingerprint string `json:"fingerprint"`
	SNI         string `json:"sni,omitempty"`
}

// LinkStatus is one link as the server's `pol status` shows it.
type LinkStatus struct {
	Addr string `json:"addr"`
	Up   bool   `json:"up"`
	Idle int64  `json:"idle"`
	Err  string `json:"err,omitempty"`
}

type link struct {
	s       *Server
	l       Link
	connect func(context.Context) (net.Conn, error)
	idle    atomic.Int64
	healthy atomic.Bool
	lastErr atomic.Value
	wake    chan struct{}
	cancel  context.CancelFunc
}

// SetLinks makes the server keep reverse connections to exactly these
// relays, starting and stopping as needed.
func (s *Server) SetLinks(links []Link) {
	want := map[string]Link{}
	for _, l := range links {
		want[l.Addr] = l
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return
	}
	if s.links == nil {
		s.links = map[string]*link{}
	}
	for addr, l := range s.links {
		if w, ok := want[addr]; !ok || w != l.l {
			l.stop()
			delete(s.links, addr)
		}
	}
	for addr, l := range want {
		if _, ok := s.links[addr]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		k := &link{s: s, l: l, connect: tlsConnect(l.Addr, l.Fingerprint, l.SNI, ProtoReverse), wake: make(chan struct{}, 1), cancel: cancel}
		k.lastErr.Store("")
		s.links[addr] = k
		go k.run(ctx)
	}
}

func (k *link) stop() { k.cancel() }

func (k *link) status() LinkStatus {
	return LinkStatus{Addr: k.l.Addr, Up: k.healthy.Load(), Idle: k.idle.Load(), Err: k.lastErr.Load().(string)}
}

func (k *link) run(ctx context.Context) {
	backoff := time.Second
	ip := hostOfString(k.l.Addr)
	for ctx.Err() == nil {
		if k.idle.Load() >= reverseWarm {
			select {
			case <-ctx.Done():
				return
			case <-k.wake:
			case <-time.After(5 * time.Second):
			}
			continue
		}
		c, err := k.dial(ctx)
		if err != nil {
			if k.healthy.Swap(false) {
				k.s.Log.Warn("reverse link down", "relay", k.l.Addr, "err", err)
			}
			k.lastErr.Store(err.Error())
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		if !k.healthy.Swap(true) {
			k.s.Log.Info("reverse link up", "relay", k.l.Addr)
		}
		k.lastErr.Store("")
		k.idle.Add(1)
		go func() {
			stop := context.AfterFunc(ctx, func() { c.Close() })
			defer stop()
			var used atomic.Bool
			k.s.serveLine(c, ip, reverseIdle, func() {
				used.Store(true)
				k.idle.Add(-1)
				k.poke()
			})
			if !used.Load() {
				k.idle.Add(-1)
				k.poke()
			}
		}()
	}
}

func (k *link) poke() {
	select {
	case k.wake <- struct{}{}:
	default:
	}
}

func (k *link) dial(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, headerTimeout)
	defer cancel()
	c, err := k.connect(ctx)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(headerTimeout))
	if _, err := io.WriteString(c, "POL1R "+k.s.Secret+"\n"); err != nil {
		c.Close()
		return nil, err
	}
	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil || b[0] != statusOK {
		c.Close()
		return nil, errors.New("the relay refused the connection - give it a current token, then run `pol link` again")
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// RelayCertFingerprint is what `pol reverse` prints for the server to pin.
func RelayCertFingerprint(c tls.Certificate) string { return certs.Fingerprint(c) }
