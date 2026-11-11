package internal_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/amor7/pol/internal/certs"
	"github.com/amor7/pol/internal/config"
	"github.com/amor7/pol/internal/relay"
	"github.com/amor7/pol/internal/tunnel"
)

// Anyone who connects to the tunnel port with the borrowed site's name and
// no secret is the real site's visitor: same certificate, same page.
func TestCamoProberGetsTheRealSite(t *testing.T) {
	r := newRig(t)
	c, err := tls.Dial("tcp", r.addr, &tls.Config{ServerName: "camo.test", RootCAs: tunnel.CamoRoots})
	if err != nil {
		t.Fatalf("the borrowed site's certificate did not check out through pol: %v", err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: camo.test\r\n\r\n")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, _ := io.ReadAll(c)
	if !strings.HasSuffix(string(b), "real site") {
		t.Fatalf("prober got %q", b)
	}
}

func TestNewModesRefuseTheWrongSecret(t *testing.T) {
	r := newRig(t)
	wc := tunnel.WSConfig{Server: r.addr, Fingerprint: r.fp, SNI: "example.com"}
	bad := map[string]relay.Dialer{
		"camo":  tunnel.NewCamoClient(r.addr, "camo.test", "wrong", 0, quiet),
		"xhttp": tunnel.NewXHTTPClient(wc, "wrong", 0, quiet),
		"ssh":   tunnel.NewSSHClient(r.addr, r.fp, "wrong", "example.com", quiet),
	}
	for name, d := range bad {
		done := make(chan error, 1)
		go func() {
			c, err := d.Dial("127.0.0.1:1")
			if err == nil {
				c.Close()
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil || errors.Is(err, tunnel.ErrRejected) {
				t.Errorf("%s with the wrong secret: err = %v", name, err)
			}
		case <-time.After(20 * time.Second):
			t.Errorf("%s with the wrong secret hung", name)
		}
	}
	// The packet modes have no handshake to fail: a session that cannot get
	// one line answered is not used.
	kcp := tunnel.NewKCPClient("127.0.0.1:1", "wrong", quiet)
	if _, err := kcp.Dial("127.0.0.1:1"); err == nil {
		t.Error("kcp to nowhere succeeded")
	}
}

// failing is a mode that never gets through.
type failing struct{}

func (failing) Dial(string) (net.Conn, error) { return nil, errors.New("blocked") }

// auto sends connections down the first mode that works and sets aside the
// ones that do not.
func TestAutoSkipsABlockedMode(t *testing.T) {
	r := newRig(t)
	target := service(t, echo)
	a := &tunnel.Auto{Spec: "auto:split,tls", Modes: []string{"split", "tls"}, Log: quiet, Get: func(m string) tunnel.Dialer {
		if m == "split" {
			return failing{}
		}
		return r.dialers[m]
	}}
	for i := range 3 {
		c, err := a.Dial(target)
		if err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		roundTrip(t, c, 1000)
		c.Close()
	}
	if st := a.Status(); !strings.Contains(st.Note, "best now: tls") {
		t.Fatalf("auto status = %+v", st)
	}
}

func TestAutoSpecs(t *testing.T) {
	for spec, ok := range map[string]bool{"auto": true, "auto:split,tls": true, "auto:": false, "auto:nope": false, "auto:direct": false, "auto:auto": false, "split": true} {
		if config.ValidMode(spec) != ok {
			t.Errorf("ValidMode(%q) = %v", spec, !ok)
		}
	}
	if m := config.AutoModes("auto:ws, xhttp"); len(m) != 2 || m[1] != "xhttp" {
		t.Fatalf("AutoModes = %v", m)
	}
}

// A middle hop passes everything on to the server behind it: the relay
// talks to the hop, the hop to the server, the server to the service.
func TestMiddleHop(t *testing.T) {
	final := newRig(t)
	cert, err := certs.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	next := tunnel.NewRawClient(final.addr, final.fp, secret, "example.com", 2, quiet)
	go next.Watch(ctx)
	mid := &tunnel.Server{Secret: "mid-secret", Log: quiet, Next: next}
	go mid.Serve(l, cert)
	defer mid.Close()

	toMid := tunnel.NewRawClient(l.Addr().String(), certs.Fingerprint(cert), "mid-secret", "example.com", 1, quiet)
	go toMid.Watch(ctx)
	c, err := toMid.Dial(service(t, echo))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	roundTrip(t, c, 1<<20)
	if got := final.server.Stats().Total; got < 1 {
		t.Fatalf("the final server saw %d streams", got)
	}
	n, err := tunnel.SpeedDown(context.Background(), toMid, 2)
	if err != nil || n != 2<<20 {
		t.Fatalf("speed through the hop: %d, %v", n, err)
	}
}
