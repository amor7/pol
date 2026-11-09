package tunnel

import (
	"bytes"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/amor7/pol/internal/certs"
)

func testServer(t *testing.T) (*Server, string) {
	t.Helper()
	cert, err := certs.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Secret: "k", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	go s.Serve(l, cert)
	t.Cleanup(func() { s.Close() })
	return s, l.Addr().String()
}

// recorder keeps a copy of everything written through it.
type recorder struct {
	net.Conn
	sent bytes.Buffer
}

func (r *recorder) Write(p []byte) (int, error) {
	r.sent.Write(p)
	return r.Conn.Write(p)
}

// A recorded obfs session played back gets nothing: not even the status
// byte that would show a pol server is there.
func TestObfsReplayGetsNothing(t *testing.T) {
	_, addr := testServer(t)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{Conn: c}
	oc, err := obfsOpen(rec, "k")
	if err != nil {
		t.Fatal(err)
	}
	if err := startLine(oc, "POL1 k @down:1", "@down:1"); err != nil {
		t.Fatalf("first session: %v", err)
	}
	c.Close()

	again, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	_, _ = again.Write(rec.sent.Bytes())
	_ = again.SetReadDeadline(time.Now().Add(12 * time.Second))
	if n, _ := again.Read(make([]byte, 1)); n != 0 {
		t.Fatal("a replayed session was answered")
	}
}

func TestObfsWrongSecretGetsNothing(t *testing.T) {
	_, addr := testServer(t)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	oc, _ := obfsOpen(c, "not the secret")
	_, _ = io.WriteString(oc, "POL1 k @down:1\n")
	_ = c.SetReadDeadline(time.Now().Add(12 * time.Second))
	if n, _ := c.Read(make([]byte, 1)); n != 0 {
		t.Fatal("the wrong secret was answered")
	}
}

// Someone poking the port with plain HTTP or a browser sees nginx.
func TestProbesSeeNginx(t *testing.T) {
	_, addr := testServer(t)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	b, _ := io.ReadAll(c)
	c.Close()
	if !strings.Contains(string(b), "nginx") || !strings.HasPrefix(string(b), "HTTP/1.1 400") {
		t.Fatalf("plain HTTP got %q", b)
	}

	tc, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}, ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(tc, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	b, _ = io.ReadAll(tc)
	tc.Close()
	if !strings.Contains(string(b), "404 Not Found") || !strings.Contains(string(b), "nginx") {
		t.Fatalf("HTTPS without the secret got %q", b)
	}
}
