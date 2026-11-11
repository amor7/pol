package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	mrand "math/rand/v2"
	"net"
	"slices"
	"testing"
	"time"
)

// helloCatcher accepts connections and keeps each one's first TLS record.
func helloCatcher(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	out := make(chan []byte, 16)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				h := make([]byte, 5)
				if _, err := io.ReadFull(c, h); err != nil {
					return
				}
				rec := make([]byte, 5+int(h[3])<<8|int(h[4]))
				copy(rec, h)
				if _, err := io.ReadFull(c, rec[5:]); err != nil {
					return
				}
				out <- rec
			}()
		}
	}()
	return addr(l), out
}

func addr(l net.Listener) string { return l.Addr().String() }

// Nothing in the clear part of a relay's connections may say pol: no
// protocol name of its own, no example.com, and Chrome's ClientHello.
func TestHelloLooksLikeChrome(t *testing.T) {
	a, got := helloCatcher(t)
	fp := "00"
	ctx := context.Background()
	wc := WSConfig{Server: a, Fingerprint: fp, SNI: LegacySNI}
	dial := map[string]func(){
		"tls":   func() { _, _ = NewRawClient(a, fp, "s", LegacySNI, 0, nil).connect(ctx) },
		"mux":   func() { _, _ = NewClient(a, fp, "s", LegacySNI, 1, nil).pool[0].http.Get("http://" + a + "/") },
		"ws":    func() { _, _ = wsConnect(wc, "s")(ctx) },
		"xhttp": func() { _, _ = NewXHTTPClient(wc, "s", 0, nil).connect(ctx) },
		"ssh":   func() { _, _ = NewSSHClient(a, fp, "s", LegacySNI, nil).key(ctx) },
		"link":  func() { _, _ = chromeConnect(a, fp, PickSNI(LegacySNI, "s", ""), nil)(ctx) },
	}
	for name, fn := range dial {
		t.Run(name, func(t *testing.T) {
			go fn()
			var rec []byte
			select {
			case rec = <-got:
			case <-time.After(10 * time.Second):
				t.Fatal("no ClientHello")
			}
			if bytes.Contains(rec, []byte("pol")) || bytes.Contains(rec, []byte(LegacySNI)) {
				t.Errorf("the ClientHello names pol or %s", LegacySNI)
			}
			if sni := helloSNI(rec); !slices.Contains(sniPool, sni) {
				t.Errorf("server name %q, want one of %v", sni, sniPool)
			}
			if !bytes.Contains(rec, []byte("http/1.1")) {
				t.Error("no http/1.1 in ALPN")
			}
			if wantH2 := name != "ws"; bytes.Contains(rec, []byte("\x02h2")) != wantH2 {
				t.Errorf("h2 offered: %v, want %v", !wantH2, wantH2)
			}
			// Chrome's hello: GREASE values (0x?a?a) lead the cipher suites.
			if len(rec) < 600 { // Chrome's, with its post-quantum key share, is well over 1 kB
				t.Errorf("ClientHello of %d bytes is not Chrome's", len(rec))
			}
		})
	}
}

// Relays from before 1.5 named pol's protocol in ALPN; servers still take them.
func TestOldRelayStillServed(t *testing.T) {
	_, a := testServer(t)
	c, err := tls.Dial("tcp", a, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{ProtoRaw}, ServerName: LegacySNI})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := startLine(c, "POL1 k "+speedUp, speedUp); err != nil {
		t.Fatal(err)
	}
}

func TestPadConnRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	want := make([]byte, 3<<20)
	_, _ = rand.Read(want)
	go func() {
		w := newPadConn(a)
		for p := want; len(p) > 0; {
			n := min(len(p), 1+mrand.IntN(40000))
			if _, err := w.Write(p[:n]); err != nil {
				t.Error(err)
				return
			}
			p = p[n:]
		}
		a.Close()
	}()
	got, err := io.ReadAll(newPadConn(b))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %d bytes back, want %d, or they differ", len(got), len(want))
	}
}
