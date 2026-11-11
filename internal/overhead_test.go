package internal_test

import (
	"context"
	"fmt"
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

// TestOverhead measures how much traffic each mode puts on the wire for the
// data it carries: every byte the server sends and receives, against the
// megabytes moved. It is what the "(+N% traffic)" labels come from. On a
// clean local link, so it counts what a mode adds by design (framing,
// encryption, spare FEC data, acknowledgements) and not resends a lossy
// path would add. Run with POL_OVERHEAD=1.
func TestOverhead(t *testing.T) {
	if os.Getenv("POL_OVERHEAD") == "" {
		t.Skip("set POL_OVERHEAD=1 to measure")
	}
	var in, out atomic.Int64
	reset := func() { in.Store(0); out.Store(0) }

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
	d := udpListen(t)
	go s.ServeKCP(tunnel.ListenDNS(countPC{d, &in, &out}, "t.test"), tunnel.ProfileDNSServer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wc := tunnel.WSConfig{Server: addr, Fingerprint: fp, SNI: "example.com"}
	tls := tunnel.NewRawClient(addr, fp, secret, "example.com", 0, quiet)
	modes := map[string]relay.Dialer{
		"tls":   tls,
		"split": tunnel.NewSplitClient(tls, secret, 4),
		"mux":   tunnel.NewClient(addr, fp, secret, "example.com", 2, quiet),
		"obfs":  tunnel.NewObfsClient(addr, secret, 0, quiet),
		"camo":  tunnel.NewCamoClient(addr, "camo.test", secret, 0, quiet),
		"ws":    tunnel.NewWSClient(wc, secret, 0, quiet),
		"xhttp": tunnel.NewXHTTPClient(wc, secret, 0, quiet),
		"ssh":   tunnel.NewSSHClient(addr, fp, secret, "example.com", quiet),
		"quic":  tunnel.NewQUICClient(addr, fp, secret, "example.com", quiet),
		"kcp":   tunnel.NewKCPClient(k.LocalAddr().String(), secret, quiet),
		"dns":   tunnel.NewDNSClient(d.LocalAddr().String(), "t.test", secret, quiet),
	}
	var names []string
	for n := range modes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		dl := modes[name]
		mb := 8
		if name == "dns" {
			mb = 1
		}
		// One stream first, so connection setup is not counted.
		if _, err := tunnel.SpeedDown(ctx, dl, 1); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		time.Sleep(200 * time.Millisecond)
		reset()
		if _, err := tunnel.SpeedDown(ctx, dl, mb); err != nil {
			t.Errorf("%s down: %v", name, err)
			continue
		}
		time.Sleep(300 * time.Millisecond)
		down := float64(in.Load()+out.Load()) / float64(mb<<20)
		reset()
		if _, err := tunnel.SpeedUp(ctx, dl, mb); err != nil {
			t.Errorf("%s up: %v", name, err)
			continue
		}
		time.Sleep(300 * time.Millisecond)
		up := float64(in.Load()+out.Load()) / float64(mb<<20)
		t.Logf("OVERHEAD %-6s down %+5.1f%%  up %+5.1f%%", name, (down-1)*100, (up-1)*100)
	}
	fmt.Fprintln(os.Stderr)
}

type countL struct {
	net.Listener
	in, out *atomic.Int64
}

func (l countL) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return countC{c, l.in, l.out}, nil
}

type countC struct {
	net.Conn
	in, out *atomic.Int64
}

func (c countC) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.in.Add(int64(n))
	return n, err
}

func (c countC) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.out.Add(int64(n))
	return n, err
}

func (c countC) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

type countPC struct {
	net.PacketConn
	in, out *atomic.Int64
}

func (c countPC) ReadFrom(p []byte) (int, net.Addr, error) {
	n, a, err := c.PacketConn.ReadFrom(p)
	c.in.Add(int64(n))
	return n, a, err
}

func (c countPC) WriteTo(p []byte, a net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, a)
	c.out.Add(int64(n))
	return n, err
}
