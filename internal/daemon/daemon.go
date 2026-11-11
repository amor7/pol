// Package daemon is `pol run`: what the systemd service executes.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/amor7/pol/internal/buildinfo"
	"github.com/amor7/pol/internal/certs"
	"github.com/amor7/pol/internal/config"
	"github.com/amor7/pol/internal/ctl"
	"github.com/amor7/pol/internal/relay"
	"github.com/amor7/pol/internal/token"
	"github.com/amor7/pol/internal/tunnel"
)

// Run serves the role in the configuration at path until a signal arrives.
func Run(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	level := slog.LevelInfo
	if os.Getenv("POL_DEBUG") == "1" {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level, ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey { // journald stamps lines itself
			return slog.Attr{}
		}
		return a
	}}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("starting pol", "version", buildinfo.Version, "role", cfg.Role)

	switch cfg.Role {
	case config.RoleServer:
		return runServer(ctx, cfg, log)
	default:
		return runRelay(ctx, cfg, log)
	}
}

// keepTrying runs open until it succeeds or ctx ends, waiting between
// tries: something may hold a port for a moment at boot.
func keepTrying(ctx context.Context, log *slog.Logger, what string, open func() error) bool {
	warned := ""
	for {
		err := open()
		if err == nil {
			return true
		}
		if err.Error() != warned {
			log.Warn("cannot open "+what+", will keep trying", "err", err)
			warned = err.Error()
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(5 * time.Second):
		}
	}
}

func links(c *config.Server) []tunnel.Link {
	out := make([]tunnel.Link, len(c.Links))
	for i, l := range c.Links {
		out[i] = tunnel.Link{Addr: l.Addr, Fingerprint: l.Fingerprint, SNI: l.SNI}
	}
	return out
}

// ---------------------------------------------------------------- server

func runServer(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	cert, err := certs.Load(cfg.Dir())
	if err != nil {
		return err
	}
	sc := cfg.Server
	s := &tunnel.Server{Secret: sc.Secret, AnyTarget: sc.AnyTarget, Log: log, Camo: sc.Camo}
	if s.Camo == "" {
		s.Camo = tunnel.DefaultCamo
	}
	started := time.Now().Unix()
	s.SetLinks(links(sc))

	// A middle hop passes everything on to the next server.
	var next *tunnels
	if sc.Next != nil {
		tok, err := token.Parse(sc.Next.Token)
		if err != nil {
			return fmt.Errorf("the next hop's token: %w", err)
		}
		mode := sc.Next.Mode
		if mode == "" {
			mode = config.ModeTLS
		}
		nr := &config.Relay{Server: tok.Server, Fingerprint: tok.Fingerprint, Secret: tok.Secret, SNI: tok.SNI, Conns: 2, Ports: []config.Forward{{Mode: mode}}}
		next = startTunnels(ctx, nr, cfg.Dir(), log)
		d := next.get(mode)
		if d == nil {
			return fmt.Errorf("the next hop's mode %q cannot be used here", mode)
		}
		s.Next = d
		log.Info("this server is a middle hop", "next", tok.Server, "mode", mode)
	}

	tunnelPort := config.PortOf(sc.Listen)
	extra := sc.Extra.Resolve(tunnelPort)
	reload := func() error {
		c, err := config.Load(cfg.Path())
		if err != nil {
			return err
		}
		if c.Role != config.RoleServer || c.Server.Secret != sc.Secret || c.Server.Listen != sc.Listen {
			return errors.New("that change needs `pol restart`")
		}
		s.SetLinks(links(c.Server))
		return nil
	}
	go func() {
		err := ctl.Serve(ctx, func() ctl.Status {
			st := s.Stats()
			ls := listening(sc, extra)
			return ctl.Status{Role: config.RoleServer, Version: buildinfo.Version, Started: started, Listen: sc.Listen, Server: &st, Listening: ls}
		}, reload, nil)
		if err != nil {
			log.Warn("control socket unavailable", "err", err)
		}
	}()

	if !sc.NoQUIC {
		go keepTrying(ctx, log, "the quic port (UDP "+sc.Listen+")", func() error {
			err := s.ServeQUIC(sc.Listen, cert)
			if ctx.Err() != nil {
				return nil
			}
			return err
		})
	}
	// The packet modes, each on its own port: kcp, hop, faketcp, dns.
	serveKCP := func(what string, open func() (net.PacketConn, error), p tunnel.KCPProfile) {
		go keepTrying(ctx, log, what, func() error {
			pc, err := open()
			if err != nil {
				return err
			}
			go func() { _ = s.ServeKCP(pc, p) }()
			return nil
		})
	}
	serveKCP("the kcp port (UDP "+strconv.Itoa(extra.KCP)+")", func() (net.PacketConn, error) {
		return net.ListenPacket("udp", ":"+strconv.Itoa(extra.KCP))
	}, tunnel.ProfileKCP)
	serveKCP(fmt.Sprintf("the hop ports (UDP %d-%d)", extra.HopLo, extra.HopHi), func() (net.PacketConn, error) {
		return tunnel.ListenHop("", extra.HopLo, extra.HopHi, log)
	}, tunnel.ProfileHop)
	if err := tunnel.FakeTCPSupported(); err != nil {
		log.Info("faketcp mode is off here", "why", err)
	} else {
		serveKCP("the faketcp port (TCP "+strconv.Itoa(extra.FakeTCP)+")", func() (net.PacketConn, error) {
			return tunnel.ListenFakeTCP(extra.FakeTCP)
		}, tunnel.ProfileFakeTCP)
	}
	if sc.DNSDomain != "" {
		serveKCP("the dns port (UDP 53)", func() (net.PacketConn, error) {
			pc, err := net.ListenPacket("udp", ":53")
			if err != nil {
				return nil, err
			}
			return tunnel.ListenDNS(pc, sc.DNSDomain), nil
		}, tunnel.ProfileDNSServer)
	}

	var l net.Listener
	if !keepTrying(ctx, log, "the tunnel port "+sc.Listen, func() (err error) {
		l, err = net.Listen("tcp", sc.Listen)
		return err
	}) {
		return nil
	}
	log.Info("server is up", "listen", sc.Listen, "kcp", extra.KCP, "hop", fmt.Sprintf("%d-%d", extra.HopLo, extra.HopHi), "faketcp", extra.FakeTCP, "dns", sc.DNSDomain != "", "camo", s.Camo)
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	if err := s.Serve(l, cert); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

// listening is what the server should be listening on, for `pol status`.
func listening(sc *config.Server, e config.ExtraPorts) []string {
	p := strconv.Itoa(config.PortOf(sc.Listen))
	out := []string{"TCP " + p + " (tls, split, mux, obfs, camo, ws, xhttp, ssh)"}
	if !sc.NoQUIC {
		out = append(out, "UDP "+p+" (quic)")
	}
	out = append(out, "UDP "+strconv.Itoa(e.KCP)+" (kcp)", fmt.Sprintf("UDP %d-%d (hop)", e.HopLo, e.HopHi))
	if tunnel.FakeTCPSupported() == nil {
		out = append(out, "TCP "+strconv.Itoa(e.FakeTCP)+" (faketcp)")
	}
	if sc.DNSDomain != "" {
		out = append(out, "UDP 53 (dns for "+sc.DNSDomain+")")
	}
	return out
}

// ---------------------------------------------------------------- relay

// mode is one way to the server, as the relay keeps it.
type mode struct {
	d      relay.Dialer
	status func() tunnel.ModeStatus
	watch  func(context.Context) // keeps it warm once a port uses it; nil if nothing to do
	once   sync.Once
	on     bool
	avail  func() error // why it cannot be used here, if it cannot
}

// tunnels is everything the relay can reach the server through.
type tunnels struct {
	ctx     context.Context
	cancel  context.CancelFunc
	r       *config.Relay
	log     *slog.Logger
	mu      sync.Mutex
	modes   map[string]*mode
	autos   map[string]*tunnel.Auto
	reverse *tunnel.ReverseListener // nil unless reverse mode is set up and listening
	mux     *tunnel.Client
}

func startTunnels(ctx context.Context, r *config.Relay, dir string, log *slog.Logger) *tunnels {
	ctx, cancel := context.WithCancel(ctx)
	host, _, _ := net.SplitHostPort(r.Server)
	extra := r.Extra.Resolve(config.PortOf(r.Server))
	t := &tunnels{ctx: ctx, cancel: cancel, r: r, log: log, modes: map[string]*mode{}, autos: map[string]*tunnel.Auto{}}
	add := func(name string, d relay.Dialer, status func() tunnel.ModeStatus, watch func(context.Context)) *mode {
		m := &mode{d: d, status: status, watch: watch}
		t.modes[name] = m
		return m
	}

	t.mux = tunnel.NewClient(r.Server, r.Fingerprint, r.Secret, r.SNI, r.Conns, log)
	tls := tunnel.NewRawClient(r.Server, r.Fingerprint, r.Secret, r.SNI, 4, log)
	splitConns := r.SplitConns
	if splitConns == 0 {
		splitConns = 4
	}
	split := tunnel.NewSplitClient(tls, r.Secret, splitConns)
	quic := tunnel.NewQUICClient(r.Server, r.Fingerprint, r.Secret, r.SNI, log)
	obfs := tunnel.NewObfsClient(r.Server, r.Secret, 2, log)
	wc := tunnel.WSConfig{Server: r.Server, Fingerprint: r.Fingerprint, SNI: r.SNI}
	if r.CDN != nil {
		wc.CDN, wc.CDNAddr, wc.CDNPort = r.CDN.Host, r.CDN.Addr, r.CDN.Port
	}
	ws := tunnel.NewWSClient(wc, r.Secret, 2, log)
	xh := tunnel.NewXHTTPClient(wc, r.Secret, 2, log)
	camo := tunnel.NewCamoClient(r.Server, r.Camo, r.Secret, 1, log)
	ssh := tunnel.NewSSHClient(r.Server, r.Fingerprint, r.Secret, r.SNI, log)
	kcp := tunnel.NewKCPClient(net.JoinHostPort(host, strconv.Itoa(extra.KCP)), r.Secret, log)
	hop := tunnel.NewHopClient(host, extra.HopLo, extra.HopHi, r.Secret, log)
	ftcp := tunnel.NewFakeTCPClient(host, extra.FakeTCP, r.Secret, log)

	// The pools that cost nothing to keep are always warm; the rest connect
	// once a port uses them.
	add(config.ModeTLS, tls, tls.Status, nil).on = true
	go tls.Watch(ctx)
	add(config.ModeSplit, split, split.Status, nil)
	add(config.ModeQUIC, quic, quic.Status, quic.Watch)
	add(config.ModeMux, t.mux, t.mux.Mode, nil).on = true
	go t.mux.Watch(ctx)
	add(config.ModeObfs, obfs, obfs.Status, obfs.Watch)
	add(config.ModeCamo, camo, camo.Status, camo.Watch)
	add(config.ModeWS, ws, func() tunnel.ModeStatus {
		st := ws.Status()
		st.Note = viaNote(r)
		return st
	}, ws.Watch)
	add(config.ModeXHTTP, xh, func() tunnel.ModeStatus {
		st := xh.Status()
		st.Note = viaNote(r)
		return st
	}, xh.Watch)
	add(config.ModeSSH, ssh, ssh.Status, ssh.Watch)
	add(config.ModeKCP, kcp, kcp.Status, kcp.Watch)
	add(config.ModeHop, hop, hop.Status, hop.Watch)
	add(config.ModeFakeTCP, ftcp, ftcp.Status, ftcp.Watch).avail = tunnel.FakeTCPSupported
	if r.DNS != nil {
		dns := tunnel.NewDNSClient(r.DNS.Resolver, r.DNS.Domain, r.Secret, log)
		add(config.ModeDNS, dns, func() tunnel.ModeStatus {
			st := dns.Status()
			st.Note = r.DNS.Domain + " via " + r.DNS.Resolver
			return st
		}, dns.Watch)
	}
	direct := tunnel.Direct{Host: host}
	add(config.ModeDirect, direct, direct.Status, nil).on = true

	if r.Reverse != nil {
		if cert, err := certs.Load(dir); err != nil {
			log.Warn("reverse mode: no certificate", "err", err)
		} else {
			go keepTrying(ctx, log, "the reverse port "+r.Reverse.Listen, func() error {
				rl, err := tunnel.ListenReverse(r.Reverse.Listen, cert, r.Secret, log)
				if err != nil {
					return err
				}
				t.mu.Lock()
				t.reverse = rl
				t.mu.Unlock()
				context.AfterFunc(ctx, func() { rl.Close() })
				log.Info("reverse mode listening", "listen", r.Reverse.Listen)
				return nil
			})
		}
	}
	t.use(r)
	return t
}

func viaNote(r *config.Relay) string {
	if r.CDN != nil {
		s := "through " + r.CDN.Host
		if r.CDN.Addr != "" {
			s += " at " + r.CDN.Addr
		}
		return s
	}
	return "straight to the server (no CDN set)"
}

// get is a mode's dialer, or nil when it cannot be used on this relay.
func (t *tunnels) get(name string) relay.Dialer {
	if name == config.ModeReverse {
		t.mu.Lock()
		defer t.mu.Unlock()
		if t.reverse == nil {
			return nil
		}
		return t.reverse
	}
	t.mu.Lock()
	m := t.modes[name]
	t.mu.Unlock()
	if m == nil || (m.avail != nil && m.avail() != nil) {
		return nil
	}
	return m.d
}

// use warms the modes the ports use and sets up the auto pickers they name.
func (t *tunnels) use(r *config.Relay) {
	for _, f := range r.Ports {
		name := f.ModeOf()
		if strings.HasPrefix(name, config.ModeAuto) {
			t.mu.Lock()
			_, ok := t.autos[name]
			if !ok {
				a := &tunnel.Auto{Spec: name, Modes: config.AutoModes(name), Get: func(m string) tunnel.Dialer {
					if d := t.get(m); d != nil {
						return d
					}
					return nil
				}, Log: t.log}
				t.autos[name] = a
				go a.Watch(t.ctx)
			}
			t.mu.Unlock()
			continue
		}
		t.mu.Lock()
		m := t.modes[name]
		t.mu.Unlock()
		if m == nil || m.watch == nil {
			continue
		}
		if m.avail != nil && m.avail() != nil {
			continue
		}
		m.once.Do(func() {
			t.mu.Lock()
			m.on = true
			t.mu.Unlock()
			go m.watch(t.ctx)
		})
	}
}

func (t *tunnels) dialers() map[string]relay.Dialer {
	d := map[string]relay.Dialer{}
	t.mu.Lock()
	names := make([]string, 0, len(t.modes))
	for n := range t.modes {
		names = append(names, n)
	}
	autos := map[string]*tunnel.Auto{}
	for k, a := range t.autos {
		autos[k] = a
	}
	t.mu.Unlock()
	for _, n := range names {
		if x := t.get(n); x != nil {
			d[n] = x
		}
	}
	if x := t.get(config.ModeReverse); x != nil {
		d[config.ModeReverse] = x
	}
	for k, a := range autos {
		d[k] = a
	}
	return d
}

func (t *tunnels) status(r *config.Relay) []tunnel.ModeStatus {
	var out []tunnel.ModeStatus
	t.mu.Lock()
	autos := make([]*tunnel.Auto, 0, len(t.autos))
	for _, a := range t.autos {
		autos = append(autos, a)
	}
	t.mu.Unlock()
	sort.Slice(autos, func(i, j int) bool { return autos[i].Spec < autos[j].Spec })
	for _, a := range autos {
		st := a.Status()
		st.Mode = a.Spec
		out = append(out, st)
	}
	for _, name := range config.Modes {
		if name == config.ModeAuto {
			continue
		}
		var st tunnel.ModeStatus
		switch name {
		case config.ModeReverse:
			t.mu.Lock()
			rl := t.reverse
			t.mu.Unlock()
			switch {
			case rl != nil:
				st = rl.Status()
			case r.Reverse != nil:
				st = tunnel.ModeStatus{Err: "cannot listen on " + r.Reverse.Listen + " - see `pol logs -e`"}
			default:
				st = tunnel.ModeStatus{Note: "not set up - `pol reverse`"}
			}
		default:
			t.mu.Lock()
			m := t.modes[name]
			on := m != nil && m.on
			t.mu.Unlock()
			switch {
			case m == nil && name == config.ModeDNS:
				st = tunnel.ModeStatus{Note: "not set up - `pol dns`"}
			case m == nil:
				continue
			case m.avail != nil && m.avail() != nil:
				st = tunnel.ModeStatus{Note: "not available here: " + m.avail().Error()}
			default:
				st = m.status()
				if !on && !st.Up && st.Err == "" && st.Note == "" {
					st.Note = "connects once a port uses it"
				}
			}
		}
		st.Mode = name
		out = append(out, st)
	}
	return out
}

func (t *tunnels) stop() {
	// The reverse port must be free before the new tunnels try to take it.
	t.mu.Lock()
	rl := t.reverse
	t.mu.Unlock()
	if rl != nil {
		rl.Close()
	}
	t.cancel()
	old := t.mux
	// Streams already open on the old tunnels finish on their own.
	time.AfterFunc(time.Minute, old.Close)
}

func runRelay(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	started := time.Now().Unix()
	var mu sync.Mutex
	r := cfg.Relay
	t := startTunnels(ctx, r, cfg.Dir(), log)
	mgr := relay.New(t.dialers(), log)
	mgr.Apply(r.Ports)
	// The reverse listener comes up a moment after the rest; hand it to the
	// ports once it is there.
	watchReverse := func(t *tunnels) {
		for range 40 {
			time.Sleep(250 * time.Millisecond)
			if t.get(config.ModeReverse) != nil {
				mu.Lock()
				mgr.SetDialers(t.dialers())
				mu.Unlock()
				return
			}
		}
	}
	if r.Reverse != nil {
		go watchReverse(t)
	}
	modTime := func() time.Time {
		if fi, err := os.Stat(cfg.Path()); err == nil {
			return fi.ModTime()
		}
		return time.Time{}
	}
	lastMod := modTime()

	reload := func() error {
		c, err := config.Load(cfg.Path())
		if err != nil {
			return err
		}
		if c.Role != config.RoleRelay {
			return fmt.Errorf("the configuration is now for a %s - use `pol restart`", c.Role)
		}
		mu.Lock()
		defer mu.Unlock()
		nr := c.Relay
		if tunnelChanged(r, nr) {
			log.Info("tunnel settings changed, reconnecting", "server", nr.Server)
			t.stop()
			t = startTunnels(ctx, nr, cfg.Dir(), log)
			if nr.Reverse != nil {
				go watchReverse(t)
			}
		} else {
			t.use(nr)
		}
		mgr.SetDialers(t.dialers())
		mgr.Apply(nr.Ports)
		r = nr
		t.r = nr
		lastMod = modTime()
		return nil
	}

	speed := func(name string, mb, streams int) (float64, float64, error) {
		mu.Lock()
		cur := t
		mu.Unlock()
		switch {
		case name == config.ModeDirect:
			return 0, 0, errors.New("direct mode goes straight to your service - nothing of pol's to measure")
		case name == config.ModeAuto:
			return 0, 0, errors.New("auto uses the other modes - measure those")
		}
		d := cur.get(name)
		if d == nil {
			switch name {
			case config.ModeReverse:
				return 0, 0, errors.New("reverse mode is not set up (`pol reverse`)")
			case config.ModeDNS:
				return 0, 0, errors.New("dns mode is not set up (`pol dns`)")
			case config.ModeFakeTCP:
				return 0, 0, tunnel.FakeTCPSupported()
			}
			return 0, 0, errors.New("unknown mode " + name)
		}
		if name == config.ModeDNS {
			mb, streams = 1, 1 // dns is far too slow for the usual test
		}
		return speedTest(d, mb, streams)
	}

	go func() {
		err := ctl.Serve(ctx, func() ctl.Status {
			mu.Lock()
			defer mu.Unlock()
			return ctl.Status{Role: config.RoleRelay, Version: buildinfo.Version, Started: started, Target: r.Server, Modes: t.status(r), Ports: mgr.Status()}
		}, reload, speed)
		if err != nil {
			log.Warn("control socket unavailable", "err", err)
		}
	}()
	log.Info("relay is up", "server", r.Server, "ports", len(r.Ports))

	// Edits made by hand are picked up too, a moment after the file changes.
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			mgr.Close()
			return nil
		case <-tick.C:
			mu.Lock()
			changed := !modTime().Equal(lastMod)
			mu.Unlock()
			if changed {
				if err := reload(); err != nil {
					log.Warn("could not read the changed configuration; keeping the old one", "err", err)
					mu.Lock()
					lastMod = modTime()
					mu.Unlock()
				}
			}
		}
	}
}

// tunnelChanged reports whether the tunnels must be rebuilt.
func tunnelChanged(a, b *config.Relay) bool {
	same := func(x, y any) bool { return fmt.Sprintf("%+v", x) == fmt.Sprintf("%+v", y) }
	if a.Server != b.Server || a.Fingerprint != b.Fingerprint || a.Secret != b.Secret || a.SNI != b.SNI || a.Conns != b.Conns || a.SplitConns != b.SplitConns || a.Camo != b.Camo {
		return true
	}
	return !same(a.CDN, b.CDN) || !same(a.Reverse, b.Reverse) || !same(a.DNS, b.DNS) || a.Extra != b.Extra
}

// speedTest moves mb megabytes each way over streams connections at once
// and returns bits per second down and up.
func speedTest(d relay.Dialer, mb, streams int) (float64, float64, error) {
	per := max(1, mb/streams)
	run := func(f func(context.Context, tunnel.Dialer, int) (int64, error)) (float64, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		var (
			wg    sync.WaitGroup
			mu    sync.Mutex
			total int64
			first error
		)
		start := time.Now()
		for range streams {
			wg.Add(1)
			go func() {
				defer wg.Done()
				n, err := f(ctx, d, per)
				mu.Lock()
				total += n
				if err != nil && first == nil {
					first = err
				}
				mu.Unlock()
			}()
		}
		wg.Wait()
		if first != nil {
			return 0, first
		}
		return float64(total*8) / time.Since(start).Seconds(), nil
	}
	down, err := run(tunnel.SpeedDown)
	if err != nil {
		return 0, 0, err
	}
	up, err := run(tunnel.SpeedUp)
	return down, up, err
}
