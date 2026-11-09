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
	"sync"
	"syscall"
	"time"

	"github.com/amor7/pol/internal/buildinfo"
	"github.com/amor7/pol/internal/certs"
	"github.com/amor7/pol/internal/config"
	"github.com/amor7/pol/internal/ctl"
	"github.com/amor7/pol/internal/relay"
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

func runServer(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	cert, err := certs.Load(cfg.Dir())
	if err != nil {
		return err
	}
	s := &tunnel.Server{Secret: cfg.Server.Secret, AnyTarget: cfg.Server.AnyTarget, Log: log}
	started := time.Now().Unix()
	s.SetLinks(links(cfg.Server))

	reload := func() error {
		c, err := config.Load(cfg.Path())
		if err != nil {
			return err
		}
		if c.Role != config.RoleServer || c.Server.Secret != cfg.Server.Secret || c.Server.Listen != cfg.Server.Listen {
			return errors.New("that change needs `pol restart`")
		}
		s.SetLinks(links(c.Server))
		return nil
	}
	go func() {
		err := ctl.Serve(ctx, func() ctl.Status {
			st := s.Stats()
			return ctl.Status{Role: config.RoleServer, Version: buildinfo.Version, Started: started, Listen: cfg.Server.Listen, Server: &st}
		}, reload, nil)
		if err != nil {
			log.Warn("control socket unavailable", "err", err)
		}
	}()

	if !cfg.Server.NoQUIC {
		go keepTrying(ctx, log, "the quic port (UDP "+cfg.Server.Listen+")", func() error {
			err := s.ServeQUIC(cfg.Server.Listen, cert)
			if ctx.Err() != nil {
				return nil
			}
			return err
		})
	}

	var l net.Listener
	if !keepTrying(ctx, log, "the tunnel port "+cfg.Server.Listen, func() (err error) {
		l, err = net.Listen("tcp", cfg.Server.Listen)
		return err
	}) {
		return nil
	}
	log.Info("server is up", "listen", cfg.Server.Listen, "quic", !cfg.Server.NoQUIC, "links", len(cfg.Server.Links))
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	if err := s.Serve(l, cert); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

// tunnels is everything the relay can reach the server through.
type tunnels struct {
	ctx     context.Context
	cancel  context.CancelFunc
	quicGo  sync.Once
	mux     *tunnel.Client
	tls     *tunnel.LineDialer
	split   *tunnel.SplitClient
	quic    *tunnel.QUICClient
	quicOn  bool
	obfs    *tunnel.LineDialer
	ws      *tunnel.LineDialer
	direct  tunnel.Direct
	mu      sync.Mutex
	reverse *tunnel.ReverseListener // nil unless reverse mode is set up and listening
}

func (t *tunnels) rev() *tunnel.ReverseListener {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.reverse
}

func startTunnels(ctx context.Context, r *config.Relay, dir string, log *slog.Logger) *tunnels {
	ctx, cancel := context.WithCancel(ctx)
	host, _, _ := net.SplitHostPort(r.Server)
	t := &tunnels{ctx: ctx, cancel: cancel, direct: tunnel.Direct{Host: host}}
	t.mux = tunnel.NewClient(r.Server, r.Fingerprint, r.Secret, r.SNI, r.Conns, log)
	t.tls = tunnel.NewRawClient(r.Server, r.Fingerprint, r.Secret, r.SNI, 4, log)
	splitConns := r.SplitConns
	if splitConns == 0 {
		splitConns = 4
	}
	t.split = tunnel.NewSplitClient(t.tls, r.Secret, splitConns)
	t.quic = tunnel.NewQUICClient(r.Server, r.Fingerprint, r.Secret, r.SNI, log)
	t.obfs = tunnel.NewObfsClient(r.Server, r.Secret, 2, log)
	wc := tunnel.WSConfig{Server: r.Server, Fingerprint: r.Fingerprint, SNI: r.SNI}
	if r.CDN != nil {
		wc.CDN, wc.CDNAddr, wc.CDNPort = r.CDN.Host, r.CDN.Addr, r.CDN.Port
	}
	t.ws = tunnel.NewWSClient(wc, r.Secret, 2, log)

	go t.mux.Watch(ctx)
	go t.tls.Watch(ctx)
	go t.obfs.Watch(ctx)
	go t.ws.Watch(ctx)
	t.useQUIC(r)

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
	return t
}

// useQUIC keeps the QUIC connection open once a port uses quic mode; until
// then it is only made when needed (a speed test).
func (t *tunnels) useQUIC(r *config.Relay) {
	for _, f := range r.Ports {
		if f.ModeOf() == config.ModeQUIC {
			t.quicGo.Do(func() {
				t.mu.Lock()
				t.quicOn = true
				t.mu.Unlock()
				go t.quic.Watch(t.ctx)
			})
			return
		}
	}
}

func (t *tunnels) dialers() map[string]relay.Dialer {
	d := map[string]relay.Dialer{
		config.ModeMux:    t.mux,
		config.ModeTLS:    t.tls,
		config.ModeSplit:  t.split,
		config.ModeQUIC:   t.quic,
		config.ModeObfs:   t.obfs,
		config.ModeWS:     t.ws,
		config.ModeDirect: t.direct,
	}
	if rl := t.rev(); rl != nil {
		d[config.ModeReverse] = rl
	}
	return d
}

func (t *tunnels) status(r *config.Relay) []tunnel.ModeStatus {
	out := []tunnel.ModeStatus{}
	add := func(mode string, st tunnel.ModeStatus) {
		st.Mode = mode
		out = append(out, st)
	}
	add(config.ModeTLS, t.tls.Status())
	add(config.ModeSplit, t.split.Status())
	q := t.quic.Status()
	t.mu.Lock()
	quicOn := t.quicOn
	t.mu.Unlock()
	if !quicOn && !q.Up && q.Err == "" {
		q.Note = "connects once a port uses it"
	}
	add(config.ModeQUIC, q)
	add(config.ModeMux, t.mux.Mode())
	add(config.ModeObfs, t.obfs.Status())
	ws := t.ws.Status()
	if r.CDN != nil {
		ws.Note = "through " + r.CDN.Host
	} else {
		ws.Note = "straight to the server (no CDN set)"
	}
	add(config.ModeWS, ws)
	if rl := t.rev(); rl != nil {
		add(config.ModeReverse, rl.Status())
	} else if r.Reverse != nil {
		add(config.ModeReverse, tunnel.ModeStatus{Err: "cannot listen on " + r.Reverse.Listen + " - see `pol logs -e`"})
	} else {
		add(config.ModeReverse, tunnel.ModeStatus{Note: "not set up - `pol reverse`"})
	}
	add(config.ModeDirect, t.direct.Status())
	return out
}

func (t *tunnels) stop() {
	// The reverse port must be free before the new tunnels try to take it.
	if rl := t.rev(); rl != nil {
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
			if t.rev() != nil {
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
			mgr.SetDialers(t.dialers())
			if nr.Reverse != nil {
				go watchReverse(t)
			}
		}
		t.useQUIC(nr)
		mgr.Apply(nr.Ports)
		r = nr
		lastMod = modTime()
		return nil
	}

	speed := func(mode string, mb, streams int) (float64, float64, error) {
		mu.Lock()
		d, ok := t.dialers()[mode]
		mu.Unlock()
		switch {
		case mode == config.ModeDirect:
			return 0, 0, errors.New("direct mode goes straight to your service - nothing of pol's to measure")
		case !ok && mode == config.ModeReverse:
			return 0, 0, errors.New("reverse mode is not set up (`pol reverse`)")
		case !ok:
			return 0, 0, errors.New("unknown mode " + mode)
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
	if a.Server != b.Server || a.Fingerprint != b.Fingerprint || a.Secret != b.Secret || a.SNI != b.SNI || a.Conns != b.Conns || a.SplitConns != b.SplitConns {
		return true
	}
	return !same(a.CDN, b.CDN) || !same(a.Reverse, b.Reverse)
}

// speedTest moves mb megabytes each way over streams connections at once
// and returns bits per second down and up.
func speedTest(d relay.Dialer, mb, streams int) (float64, float64, error) {
	per := max(1, mb/streams)
	run := func(f func(context.Context, tunnel.Dialer, int) (int64, error)) (float64, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
