package internal_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/amor7/pol/internal/certs"
	"github.com/amor7/pol/internal/config"
	"github.com/amor7/pol/internal/relay"
	"github.com/amor7/pol/internal/token"
	"github.com/amor7/pol/internal/tunnel"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type rig struct {
	t      *testing.T
	server *tunnel.Server
	client *tunnel.Client
	mgr    *relay.Manager
	addr   string
	fp     string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	cert, err := certs.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &tunnel.Server{Secret: "s3cret", Log: quiet}
	go s.Serve(l, cert)
	t.Cleanup(func() { s.Close() })
	r := &rig{t: t, server: s, addr: l.Addr().String(), fp: certs.Fingerprint(cert)}
	r.client = tunnel.NewClient(r.addr, r.fp, "s3cret", "example.com", 2, quiet)
	t.Cleanup(r.client.Close)
	r.mgr = relay.New(r.client, quiet)
	t.Cleanup(r.mgr.Close)
	return r
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// service starts a TCP service on loopback that runs fn per connection.
func service(t *testing.T, fn func(net.Conn)) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				fn(c)
			}()
		}
	}()
	return l.Addr().String()
}

func echo(c net.Conn) { _, _ = io.Copy(c, c) }

// forward makes the relay listen on a fresh port for target and waits for
// it to open.
func (r *rig) forward(target string) int {
	r.t.Helper()
	p := freePort(r.t)
	r.mgr.Apply([]config.Forward{{Listen: p, Target: target}})
	r.waitOpen(p)
	return p
}

func (r *rig) waitOpen(p int) {
	r.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, s := range r.mgr.Status() {
			if s.Listen == p && s.Open {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	r.t.Fatalf("port %d never opened: %+v", p, r.mgr.Status())
}

func dial(t *testing.T, p int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(p), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func roundTrip(t *testing.T, c net.Conn, size int) {
	t.Helper()
	msg := make([]byte, size)
	_, _ = rand.Read(msg)
	go func() { _, _ = c.Write(msg) }()
	got := make([]byte, size)
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("echo of %d bytes: %v", size, err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo of %d bytes came back different", size)
	}
}

func TestForwardEcho(t *testing.T) {
	r := newRig(t)
	p := r.forward(service(t, echo))
	c := dial(t, p)
	defer c.Close()
	roundTrip(t, c, 10)
	roundTrip(t, c, 1<<20)

	st := r.mgr.Status()[0]
	if st.Active != 1 || st.Total != 1 || st.Up < 1<<20 || st.Down < 1<<20 {
		t.Fatalf("port counters = %+v", st)
	}
}

func TestManyConnectionsAtOnce(t *testing.T) {
	r := newRig(t)
	p := r.forward(service(t, echo))
	var wg sync.WaitGroup
	for range 60 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := dial(t, p)
			defer c.Close()
			roundTrip(t, c, 128<<10)
		}()
	}
	wg.Wait()
}

func TestLargeDownloadAndHalfClose(t *testing.T) {
	r := newRig(t)
	const size = 48 << 20
	// The service reads the whole request, then answers; the user closes
	// their sending side first, as an HTTP/1.0 client might.
	target := service(t, func(c net.Conn) {
		n, _ := io.Copy(io.Discard, c)
		if n != 5 {
			return
		}
		_, _ = io.CopyN(c, zeroReader{}, size)
	})
	p := r.forward(target)
	c := dial(t, p).(*net.TCPConn)
	defer c.Close()
	_, _ = c.Write([]byte("hello"))
	_ = c.CloseWrite()
	_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
	n, err := io.Copy(io.Discard, c)
	if err != nil || n != size {
		t.Fatalf("got %d bytes, err %v; want %d", n, err, size)
	}
}

// One user whose upload is not being read (the service is busy or stuck)
// must not hold up anyone else on the same tunnel connection. With Go's
// default windows (1 MB per connection) this is exactly what happened.
func TestStalledUserDoesNotBlockOthers(t *testing.T) {
	r := newRig(t)
	// One tunnel connection, so both users share it: with two, the second
	// would simply land on the other one and the test would prove nothing.
	one := tunnel.NewClient(r.addr, r.fp, "s3cret", "example.com", 1, quiet)
	t.Cleanup(one.Close)
	r.mgr.SetDialer(one)

	release := make(chan struct{})
	defer close(release)
	sink := service(t, func(c net.Conn) { <-release }) // accepts, never reads
	stuckPort := r.forward(sink)
	stuck := dial(t, stuckPort)
	defer stuck.Close()
	go func() { _, _ = io.CopyN(stuck, zeroReader{}, 256<<20) }()
	time.Sleep(time.Second) // let the upload pile up in the tunnel

	p := freePort(t)
	r.mgr.Apply([]config.Forward{{Listen: stuckPort, Target: sink}, {Listen: p, Target: service(t, echo)}})
	r.waitOpen(p)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c := dial(t, p)
		defer c.Close()
		// More than the operating system will buffer for the stuck one, so
		// this only gets through if the tunnel's windows leave it room.
		roundTrip(t, c, 8<<20)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a stalled upload blocked another user")
	}
}

func TestPortsComeAndGo(t *testing.T) {
	r := newRig(t)
	target := service(t, echo)
	p := r.forward(target)
	c := dial(t, p)
	roundTrip(t, c, 100)

	r.mgr.Apply(nil)
	// The open connection is cut and the port no longer answers.
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection survived its port being removed")
	}
	c.Close()
	if c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(p), time.Second); err == nil {
		c.Close()
		t.Fatal("removed port still accepts connections")
	}

	r.mgr.Apply([]config.Forward{{Listen: p, Target: target}})
	r.waitOpen(p)
	c = dial(t, p)
	defer c.Close()
	roundTrip(t, c, 100)
}

// A port held by something else at start is taken once it is let go.
func TestBusyPortIsRetried(t *testing.T) {
	r := newRig(t)
	holder, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	p := holder.Addr().(*net.TCPAddr).Port
	r.mgr.Apply([]config.Forward{{Listen: p, Target: service(t, echo)}})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if st := r.mgr.Status(); len(st) == 1 && st[0].Err != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("busy port shows no error: %+v", r.mgr.Status())
		}
		time.Sleep(20 * time.Millisecond)
	}
	holder.Close()
	r.waitOpen(p)
	c := dial(t, p)
	defer c.Close()
	roundTrip(t, c, 100)
}

func TestWrongSecretAndForeignTargets(t *testing.T) {
	r := newRig(t)
	bad := tunnel.NewClient(r.addr, r.fp, "wrong", "example.com", 1, quiet)
	defer bad.Close()
	if _, err := bad.Dial("127.0.0.1:1"); err == nil || errors.Is(err, tunnel.ErrRejected) {
		t.Fatalf("wrong secret: err = %v", err)
	}
	if _, err := bad.Ping(context.Background()); err == nil {
		t.Fatal("wrong secret pinged")
	}

	if _, err := r.client.Dial("10.255.255.1:80"); !errors.Is(err, tunnel.ErrRejected) {
		t.Fatalf("another machine's port: err = %v", err)
	}
	if _, err := r.client.Dial("127.0.0.1:" + strconv.Itoa(freePort(t))); !errors.Is(err, tunnel.ErrRejected) {
		t.Fatalf("closed local port: err = %v", err)
	}

	// The wrong certificate is refused outright.
	other, _ := certs.Load(t.TempDir())
	imp := tunnel.NewClient(r.addr, certs.Fingerprint(other), "s3cret", "example.com", 1, quiet)
	defer imp.Close()
	if _, err := imp.Ping(context.Background()); err == nil {
		t.Fatal("a server with another certificate was trusted")
	}
}

func TestPingAndSpeed(t *testing.T) {
	r := newRig(t)
	if _, err := r.client.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	down, up, err := r.client.Speed(context.Background(), 4)
	if err != nil || down <= 0 || up <= 0 {
		t.Fatalf("speed: %v %v %v", down, up, err)
	}
}

func TestParseForwards(t *testing.T) {
	got, err := config.ParseForwards([]string{"2088", "2089:443,2090:10.0.0.5:443", "3000-3002"})
	if err != nil {
		t.Fatal(err)
	}
	want := []config.Forward{
		{Listen: 2088, Target: "127.0.0.1:2088"},
		{Listen: 2089, Target: "127.0.0.1:443"},
		{Listen: 2090, Target: "10.0.0.5:443"},
		{Listen: 3000, Target: "127.0.0.1:3000"},
		{Listen: 3001, Target: "127.0.0.1:3001"},
		{Listen: 3002, Target: "127.0.0.1:3002"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	for _, bad := range []string{"0", "70000", "abc", "3000-2000", "1-5000", "3000-3002:80", "2088:x"} {
		if _, err := config.ParseForwards([]string{bad}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestToken(t *testing.T) {
	tok := token.Token{Server: "1.2.3.4:443", Fingerprint: "ab", Secret: "k", SNI: "example.com"}
	s := tok.String()
	// Copying out of a terminal adds line breaks.
	got, err := token.Parse(" " + s[:20] + "\n" + s[20:] + " ")
	if err != nil || got != tok {
		t.Fatalf("got %+v, %v", got, err)
	}
	if _, err := token.Parse("gz1_abc"); err == nil {
		t.Fatal("a foreign token was accepted")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
