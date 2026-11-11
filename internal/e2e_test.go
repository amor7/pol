package internal_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"os"
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

const secret = "s3cret"

// slow modes are left out of the tests that move many megabytes.
var slow = map[string]bool{config.ModeDNS: true}

// rig is a server and a relay on this machine with every mode set up.
type rig struct {
	t       *testing.T
	server  *tunnel.Server
	addr    string
	fp      string
	mux     *tunnel.Client
	tls     *tunnel.LineDialer
	dialers map[string]relay.Dialer
	mgr     *relay.Manager
}

// camoSite is a stand-in for the real website camo mode borrows: its own
// certificate authority, which the relay is told to trust, and a page.
func camoSite(t *testing.T) string {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafT := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "camo.test"}, DNSNames: []string{"camo.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafT, ca, &key.PublicKey, caKey)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	tunnel.CamoRoots = pool
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: key}}, NextProtos: []string{"http/1.1"}})
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
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))
				br := bufio.NewReader(c)
				if _, err := br.ReadString('\n'); err != nil {
					return
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nreal site")
			}()
		}
	}()
	return l.Addr().String()
}

func udpListen(t *testing.T) net.PacketConn {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc
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
	s := &tunnel.Server{Secret: secret, Log: quiet, Camo: "camo.test", CamoAddr: camoSite(t)}
	go s.Serve(l, cert)
	go s.ServeQUIC(l.Addr().String(), cert) // same port number, over UDP
	t.Cleanup(func() { s.Close() })
	r := &rig{t: t, server: s, addr: l.Addr().String(), fp: certs.Fingerprint(cert)}

	// The packet modes' listeners.
	kcpPC := udpListen(t)
	go s.ServeKCP(kcpPC, tunnel.ProfileKCP)
	var hopLo int
	var hopPC net.PacketConn
	for try := 0; try < 50 && hopPC == nil; try++ {
		lo := 30000 + mrand.IntN(30000)
		if pc, err := tunnel.ListenHop("127.0.0.1", lo, lo+3, quiet); err == nil && pc != nil {
			hopLo, hopPC = lo, pc
		}
	}
	if hopPC == nil {
		t.Fatal("no free port range for hop")
	}
	t.Cleanup(func() { hopPC.Close() })
	go s.ServeKCP(hopPC, tunnel.ProfileHop)
	dnsPC := udpListen(t)
	go s.ServeKCP(tunnel.ListenDNS(dnsPC, "t.test"), tunnel.ProfileDNSServer)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r.mux = tunnel.NewClient(r.addr, r.fp, secret, "example.com", 2, quiet)
	t.Cleanup(r.mux.Close)
	r.tls = tunnel.NewRawClient(r.addr, r.fp, secret, "example.com", 2, quiet)
	go r.tls.Watch(ctx)
	obfs := tunnel.NewObfsClient(r.addr, secret, 2, quiet)
	go obfs.Watch(ctx)
	wc := tunnel.WSConfig{Server: r.addr, Fingerprint: r.fp, SNI: "example.com"}
	ws := tunnel.NewWSClient(wc, secret, 2, quiet)
	go ws.Watch(ctx)
	xh := tunnel.NewXHTTPClient(wc, secret, 2, quiet)
	go xh.Watch(ctx)
	camo := tunnel.NewCamoClient(r.addr, "camo.test", secret, 1, quiet)
	go camo.Watch(ctx)
	ssh := tunnel.NewSSHClient(r.addr, r.fp, secret, "example.com", quiet)
	go ssh.Watch(ctx)
	quic := tunnel.NewQUICClient(r.addr, r.fp, secret, "example.com", quiet)
	go quic.Watch(ctx)
	kcp := tunnel.NewKCPClient(kcpPC.LocalAddr().String(), secret, quiet)
	go kcp.Watch(ctx)
	hop := tunnel.NewHopClient("127.0.0.1", hopLo, hopLo+3, secret, quiet)
	go hop.Watch(ctx)
	dns := tunnel.NewDNSClient(dnsPC.LocalAddr().String(), "t.test", secret, quiet)
	go dns.Watch(ctx)

	// Reverse: the relay listens with its own certificate; the server links.
	relayCert, err := certs.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rev, err := tunnel.ListenReverse("127.0.0.1:0", relayCert, secret, quiet)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rev.Close() })
	s.SetLinks([]tunnel.Link{{Addr: rev.Addr().String(), Fingerprint: certs.Fingerprint(relayCert)}})

	r.dialers = map[string]relay.Dialer{
		config.ModeMux:     r.mux,
		config.ModeTLS:     r.tls,
		config.ModeSplit:   tunnel.NewSplitClient(r.tls, secret, 4),
		config.ModeQUIC:    quic,
		config.ModeObfs:    obfs,
		config.ModeCamo:    camo,
		config.ModeWS:      ws,
		config.ModeXHTTP:   xh,
		config.ModeSSH:     ssh,
		config.ModeKCP:     kcp,
		config.ModeHop:     hop,
		config.ModeDNS:     dns,
		config.ModeReverse: rev,
		config.ModeDirect:  tunnel.Direct{Host: "127.0.0.1"},
	}
	// faketcp needs raw sockets: Linux, as root, with iptables.
	if tunnel.FakeTCPSupported() == nil && os.Geteuid() == 0 {
		fp := freePort(t)
		if pc, err := tunnel.ListenFakeTCP(fp); err == nil {
			t.Cleanup(func() { pc.Close() })
			go s.ServeKCP(pc, tunnel.ProfileFakeTCP)
			ft := tunnel.NewFakeTCPClient("127.0.0.1", fp, secret, quiet)
			go ft.Watch(ctx)
			r.dialers[config.ModeFakeTCP] = ft
		} else {
			t.Logf("faketcp left out: %v", err)
		}
	}
	auto := &tunnel.Auto{Spec: config.ModeAuto, Modes: config.AutoModes(config.ModeAuto), Log: quiet, Get: func(m string) tunnel.Dialer {
		if d, ok := r.dialers[m]; ok {
			return d
		}
		return nil
	}}
	r.dialers[config.ModeAuto] = auto
	r.mgr = relay.New(r.dialers, quiet)
	t.Cleanup(r.mgr.Close)
	return r
}

func fakeTCPHere() bool { return tunnel.FakeTCPSupported() == nil && os.Geteuid() == 0 }

// eachMode runs fn as a subtest for every tunnel mode set up here.
func eachMode(t *testing.T, fn func(t *testing.T, mode string)) {
	for _, m := range config.Modes {
		t.Run(m, func(t *testing.T) {
			if m == config.ModeFakeTCP && !fakeTCPHere() {
				t.Skip("faketcp needs Linux, root and iptables")
			}
			fn(t, m)
		})
	}
}

// heavy is eachMode without the slow modes, for tests that move a lot.
func heavy(t *testing.T, fn func(t *testing.T, mode string)) {
	eachMode(t, func(t *testing.T, m string) {
		if slow[m] {
			t.Skip(m + " is too slow for this test")
		}
		fn(t, m)
	})
}

// tunnelled is every mode that goes through pol's server (not direct).
func tunnelled(t *testing.T, fn func(t *testing.T, mode string)) {
	eachMode(t, func(t *testing.T, m string) {
		if m == config.ModeDirect {
			t.Skip("direct does not go through pol")
		}
		fn(t, m)
	})
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

// udpEcho starts a UDP echo service on loopback.
func udpEcho(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65536)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], a)
		}
	}()
	return pc.LocalAddr().String()
}

// forward makes the relay listen on a fresh port for target and waits for
// it to open.
func (r *rig) forward(target, mode string) int {
	r.t.Helper()
	p := freePort(r.t)
	r.mgr.Apply([]config.Forward{{Listen: p, Target: target, Mode: mode}})
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
	eachMode(t, func(t *testing.T, mode string) {
		r := newRig(t)
		p := r.forward(service(t, echo), mode)
		c := dial(t, p)
		defer c.Close()
		roundTrip(t, c, 10)
		roundTrip(t, c, 1<<20)

		// Counters are added just after each write, so give them a moment.
		var st relay.PortStatus
		for range 100 {
			st = r.mgr.Status()[0]
			if st.Active == 1 && st.Total == 1 && st.Up >= 1<<20 && st.Down >= 1<<20 {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("port counters = %+v", st)
	})
}

func TestManyConnectionsAtOnce(t *testing.T) {
	heavy(t, func(t *testing.T, mode string) {
		r := newRig(t)
		p := r.forward(service(t, echo), mode)
		var wg sync.WaitGroup
		for range 40 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c := dial(t, p)
				defer c.Close()
				roundTrip(t, c, 128<<10)
			}()
		}
		wg.Wait()
	})
}

// The service reads the whole request, then answers; the user closes their
// sending side first, as an HTTP/1.0 client might.
func TestLargeDownloadAndHalfClose(t *testing.T) {
	heavy(t, func(t *testing.T, mode string) {
		r := newRig(t)
		const size = 32 << 20
		target := service(t, func(c net.Conn) {
			n, _ := io.Copy(io.Discard, c)
			if n != 5 {
				return
			}
			_, _ = io.CopyN(c, zeroReader{}, size)
		})
		p := r.forward(target, mode)
		c := dial(t, p).(*net.TCPConn)
		defer c.Close()
		_, _ = c.Write([]byte("hello"))
		_ = c.CloseWrite()
		_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := io.Copy(io.Discard, c)
		if err != nil || n != size {
			t.Fatalf("got %d bytes, err %v; want %d", n, err, size)
		}
	})
}

// A large upload arrives intact and in order (split reorders chunks that
// arrive over different connections).
func TestLargeUploadIntact(t *testing.T) {
	heavy(t, func(t *testing.T, mode string) {
		r := newRig(t)
		const size = 16 << 20
		sum := make(chan []byte, 1)
		target := service(t, func(c net.Conn) {
			got, _ := io.ReadAll(c)
			sum <- got
			_, _ = c.Write([]byte("ok"))
		})
		p := r.forward(target, mode)
		c := dial(t, p).(*net.TCPConn)
		defer c.Close()
		msg := make([]byte, size)
		_, _ = rand.Read(msg)
		go func() {
			_, _ = c.Write(msg)
			_ = c.CloseWrite()
		}()
		select {
		case got := <-sum:
			if !bytes.Equal(got, msg) {
				t.Fatalf("upload arrived different (%d bytes)", len(got))
			}
		case <-time.After(60 * time.Second):
			t.Fatal("upload did not arrive")
		}
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		if b, _ := io.ReadAll(c); string(b) != "ok" {
			t.Fatalf("answer after upload = %q", b)
		}
	})
}

func TestUDP(t *testing.T) {
	eachMode(t, func(t *testing.T, mode string) {
		r := newRig(t)
		target := udpEcho(t)
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := pc.LocalAddr().(*net.UDPAddr).Port
		pc.Close()
		r.mgr.Apply([]config.Forward{{Listen: p, Target: target, Mode: mode, Proto: "udp"}})
		r.waitOpen(p)

		c, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(p))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		buf := make([]byte, 2000)
		for i := range 30 {
			msg := []byte("datagram " + strconv.Itoa(i))
			got := false
			for try := 0; try < 5 && !got; try++ { // UDP may drop; ask again
				_, _ = c.Write(msg)
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, err := c.Read(buf)
				got = err == nil && bytes.Equal(buf[:n], msg)
			}
			if !got {
				t.Fatalf("datagram %d did not come back", i)
			}
		}
		if st := r.mgr.Status()[0]; st.Proto != "udp" || st.Total != 1 || st.Active != 1 {
			t.Fatalf("udp port = %+v", st)
		}
	})
}

// One user whose upload is not being read (the service is busy or stuck)
// must not hold up anyone else on the same tunnel connection. With Go's
// default windows (1 MB per connection) this is exactly what happened.
func TestStalledUserDoesNotBlockOthers(t *testing.T) {
	r := newRig(t)
	// One tunnel connection, so both users share it: with two, the second
	// would simply land on the other one and the test would prove nothing.
	one := tunnel.NewClient(r.addr, r.fp, secret, "example.com", 1, quiet)
	t.Cleanup(one.Close)
	r.mgr.SetDialers(map[string]relay.Dialer{config.ModeMux: one})

	release := make(chan struct{})
	defer close(release)
	sink := service(t, func(c net.Conn) { <-release }) // accepts, never reads
	stuckPort := r.forward(sink, config.ModeMux)
	stuck := dial(t, stuckPort)
	defer stuck.Close()
	go func() { _, _ = io.CopyN(stuck, zeroReader{}, 256<<20) }()
	time.Sleep(time.Second) // let the upload pile up in the tunnel

	p := freePort(t)
	r.mgr.Apply([]config.Forward{{Listen: stuckPort, Target: sink, Mode: config.ModeMux}, {Listen: p, Target: service(t, echo), Mode: config.ModeMux}})
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
	p := r.forward(target, config.ModeTLS)
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

// Changing a port's mode cuts its open connections, so clients reconnect
// through the new mode at once; other ports are left alone.
func TestModeSwitchReconnectsAtOnce(t *testing.T) {
	r := newRig(t)
	target := service(t, echo)
	p, other := freePort(t), freePort(t)
	fs := []config.Forward{{Listen: p, Target: target, Mode: config.ModeMux}, {Listen: other, Target: target, Mode: config.ModeTLS}}
	r.mgr.Apply(fs)
	r.waitOpen(p)
	r.waitOpen(other)
	before := dial(t, p)
	defer before.Close()
	roundTrip(t, before, 100)
	bystander := dial(t, other)
	defer bystander.Close()
	roundTrip(t, bystander, 100)

	fs[0].Mode = config.ModeQUIC
	r.mgr.Apply(fs)
	_ = before.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := before.Read(make([]byte, 1)); err == nil {
		t.Fatal("the open connection stayed on the old mode")
	}
	roundTrip(t, bystander, 100) // another port's user is not touched

	after := dial(t, p)
	defer after.Close()
	roundTrip(t, after, 100)
	q := r.dialers[config.ModeQUIC].(*tunnel.QUICClient).Status().Open
	if q != 1 {
		t.Fatalf("quic streams open = %d, want 1", q)
	}
	for range 100 {
		if r.mux.Mode().Open == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("mux streams still open: %d", r.mux.Mode().Open)
}

func TestUDPModeSwitchReconnects(t *testing.T) {
	r := newRig(t)
	target := udpEcho(t)
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	p := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	f := config.Forward{Listen: p, Target: target, Mode: config.ModeTLS, Proto: "udp"}
	r.mgr.Apply([]config.Forward{f})
	r.waitOpen(p)
	c, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(p))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ping := func() bool {
		buf := make([]byte, 100)
		for range 5 {
			_, _ = c.Write([]byte("x"))
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			if n, err := c.Read(buf); err == nil && n == 1 {
				return true
			}
		}
		return false
	}
	if !ping() {
		t.Fatal("no echo before the switch")
	}
	f.Mode = config.ModeQUIC
	r.mgr.Apply([]config.Forward{f})
	if !ping() {
		t.Fatal("no echo after the switch")
	}
	if q := r.dialers[config.ModeQUIC].(*tunnel.QUICClient).Status().Open; q != 1 {
		t.Fatalf("the client did not move to quic (quic streams = %d)", q)
	}
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

func TestWrongSecretIsRefused(t *testing.T) {
	r := newRig(t)
	bad := map[string]relay.Dialer{
		"mux":  tunnel.NewClient(r.addr, r.fp, "wrong", "example.com", 1, quiet),
		"tls":  tunnel.NewRawClient(r.addr, r.fp, "wrong", "example.com", 0, quiet),
		"obfs": tunnel.NewObfsClient(r.addr, "wrong", 0, quiet),
		"ws":   tunnel.NewWSClient(tunnel.WSConfig{Server: r.addr, Fingerprint: r.fp}, "wrong", 0, quiet),
		"quic": tunnel.NewQUICClient(r.addr, r.fp, "wrong", "example.com", quiet),
	}
	for name, d := range bad {
		if _, err := d.Dial("127.0.0.1:1"); err == nil || errors.Is(err, tunnel.ErrRejected) {
			t.Errorf("%s with the wrong secret: err = %v", name, err)
		}
	}
	// The wrong certificate is refused outright.
	other, _ := certs.Load(t.TempDir())
	imp := tunnel.NewClient(r.addr, certs.Fingerprint(other), secret, "example.com", 1, quiet)
	defer imp.Close()
	if _, err := imp.Ping(context.Background()); err == nil {
		t.Fatal("a server with another certificate was trusted")
	}
}

func TestForeignAndClosedTargetsAreRefused(t *testing.T) {
	tunnelled(t, func(t *testing.T, mode string) {
		r := newRig(t)
		d := r.dialers[mode]
		if _, err := d.Dial("10.255.255.1:80"); !errors.Is(err, tunnel.ErrRejected) {
			t.Fatalf("another machine's port: err = %v", err)
		}
		if _, err := d.Dial("127.0.0.1:" + strconv.Itoa(freePort(t))); !errors.Is(err, tunnel.ErrRejected) {
			t.Fatalf("closed local port: err = %v", err)
		}
	})
}

func TestSpeedThroughEveryMode(t *testing.T) {
	tunnelled(t, func(t *testing.T, mode string) {
		r := newRig(t)
		ctx := context.Background()
		d := r.dialers[mode]
		down, err := tunnel.SpeedDown(ctx, d, 3)
		if err != nil || down != 3<<20 {
			t.Fatalf("download: %d, %v", down, err)
		}
		up, err := tunnel.SpeedUp(ctx, d, 3)
		if err != nil || up != 3<<20 {
			t.Fatalf("upload: %d, %v", up, err)
		}
	})
}

func TestParseForwards(t *testing.T) {
	got, err := config.ParseForwards([]string{"2088", "2089:443,2090:10.0.0.5:443", "3000-3002", "443/udp", "53:5353/udp"})
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
		{Listen: 443, Target: "127.0.0.1:443", Proto: "udp"},
		{Listen: 53, Target: "127.0.0.1:5353", Proto: "udp"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	for _, bad := range []string{"0", "70000", "abc", "3000-2000", "1-5000", "3000-3002:80", "2088:x", "53/sctp"} {
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
