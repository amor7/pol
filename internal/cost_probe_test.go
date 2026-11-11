package internal_test

import (
	"context"
	"io"
	"net"
	"os"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amor7/pol/internal/certs"
	"github.com/amor7/pol/internal/relay"
	"github.com/amor7/pol/internal/tunnel"
)

// TestCostProbe measures what TestOverhead leaves out: the bytes it takes
// to open one connection and carry a small exchange, and what each mode
// costs while nobody uses it. Run with POL_COST=1.
func TestCostProbe(t *testing.T) {
	if os.Getenv("POL_COST") == "" {
		t.Skip("set POL_COST=1")
	}
	var in, out atomic.Int64
	total := func() int64 { return in.Load() + out.Load() }
	cert, _ := certs.Load(t.TempDir())
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	s := &tunnel.Server{Secret: secret, Log: quiet, Camo: "camo.test", CamoAddr: camoSite(t)}
	go s.Serve(countL{l, &in, &out}, cert)
	defer s.Close()
	addr := l.Addr().String()
	fp := certs.Fingerprint(cert)
	q, _ := net.ListenPacket("udp", addr)
	go s.ServeQUICConn(countPC{q, &in, &out}, cert)
	k := udpListen(t)
	go s.ServeKCP(countPC{k, &in, &out}, tunnel.ProfileKCP)
	target := service(t, echo)
	wc := tunnel.WSConfig{Server: addr, Fingerprint: fp, SNI: "example.com"}

	type mk func(warm int) (relay.Dialer, func(context.Context))
	modes := map[string]mk{
		"tls": func(w int) (relay.Dialer, func(context.Context)) {
			d := tunnel.NewRawClient(addr, fp, secret, "example.com", w, quiet)
			return d, d.Watch
		},
		"split": func(w int) (relay.Dialer, func(context.Context)) {
			b := tunnel.NewRawClient(addr, fp, secret, "example.com", w, quiet)
			return tunnel.NewSplitClient(b, secret, 4), b.Watch
		},
		"mux": func(int) (relay.Dialer, func(context.Context)) {
			d := tunnel.NewClient(addr, fp, secret, "example.com", 2, quiet)
			return d, d.Watch
		},
		"obfs": func(w int) (relay.Dialer, func(context.Context)) {
			d := tunnel.NewObfsClient(addr, secret, w, quiet)
			return d, d.Watch
		},
		"camo": func(w int) (relay.Dialer, func(context.Context)) {
			d := tunnel.NewCamoClient(addr, "camo.test", secret, w, quiet)
			return d, d.Watch
		},
		"ws": func(w int) (relay.Dialer, func(context.Context)) {
			d := tunnel.NewWSClient(wc, secret, w, quiet)
			return d, d.Watch
		},
		"shield": func(w int) (relay.Dialer, func(context.Context)) {
			d := tunnel.NewRawClient(addr, fp, secret, "example.com", w, quiet)
			return tunnel.Shield{L: d}, d.Watch
		},
		"shield-cdn": func(w int) (relay.Dialer, func(context.Context)) {
			d := tunnel.NewXHTTPClient(wc, secret, w, quiet)
			return tunnel.Shield{L: d}, d.Watch
		},
		"xhttp": func(w int) (relay.Dialer, func(context.Context)) {
			d := tunnel.NewXHTTPClient(wc, secret, w, quiet)
			return d, d.Watch
		},
		"ssh": func(int) (relay.Dialer, func(context.Context)) {
			d := tunnel.NewSSHClient(addr, fp, secret, "example.com", quiet)
			return d, d.Watch
		},
		"quic": func(int) (relay.Dialer, func(context.Context)) {
			d := tunnel.NewQUICClient(addr, fp, secret, "example.com", quiet)
			return d, d.Watch
		},
		"kcp": func(int) (relay.Dialer, func(context.Context)) {
			d := tunnel.NewKCPClient(k.LocalAddr().String(), secret, quiet)
			return d, d.Watch
		},
	}
	warmOf := map[string]int{"tls": 2, "split": 2, "obfs": 1, "camo": 1, "ws": 1, "xhttp": 1}
	var names []string
	for n := range modes {
		names = append(names, n)
	}
	sort.Strings(names)
	idleFor := 90 * time.Second // long enough to see a few pool refreshes
	if v := os.Getenv("POL_COST_IDLE"); v != "" {
		idleFor, _ = time.ParseDuration(v)
	}
	for _, name := range names {
		// Per connection, with nothing kept ready: open, 1 kB each way, close.
		d, _ := modes[name](0)
		c, err := d.Dial(target) // first one also sets up whatever is shared
		if err == nil {
			c.Close()
		}
		time.Sleep(300 * time.Millisecond)
		in.Store(0)
		out.Store(0)
		const n = 10
		for range n {
			c, err := d.Dial(target)
			if err != nil {
				t.Errorf("%s: %v", name, err)
				break
			}
			msg := make([]byte, 1024)
			go func() { _, _ = c.Write(msg) }()
			_, _ = io.ReadFull(c, make([]byte, 1024))
			c.Close()
		}
		time.Sleep(300 * time.Millisecond)
		perConn := total() / n

		// Idle: what keeping it ready costs, with nobody using it.
		d, watch := modes[name](warmOf[name])
		ctx, cancel := context.WithCancel(context.Background())
		go watch(ctx)
		_ = d
		time.Sleep(5 * time.Second) // let it settle
		in.Store(0)
		out.Store(0)
		time.Sleep(idleFor)
		idle := float64(total()) / idleFor.Seconds()
		cancel()
		time.Sleep(time.Second)
		t.Logf("COST %-6s per connection (1 kB each way): %6d bytes   idle: %7.0f bytes/s = %5.1f MB/day", name, perConn, idle, idle*86400/1e6)
	}
}
