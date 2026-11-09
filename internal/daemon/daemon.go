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

func runServer(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	cert, err := certs.Load(cfg.Dir())
	if err != nil {
		return err
	}
	s := &tunnel.Server{Secret: cfg.Server.Secret, AnyTarget: cfg.Server.AnyTarget, Log: log}
	started := time.Now().Unix()

	go func() {
		err := ctl.Serve(ctx, func() ctl.Status {
			st := s.Stats()
			return ctl.Status{Role: config.RoleServer, Version: buildinfo.Version, Started: started, Listen: cfg.Server.Listen, Server: &st}
		}, func() error { return errors.New("the server has nothing to reload - use `pol restart`") })
		if err != nil {
			log.Warn("control socket unavailable", "err", err)
		}
	}()

	// Keep trying the port: something may hold it for a moment at boot.
	var l net.Listener
	for {
		l, err = net.Listen("tcp", cfg.Server.Listen)
		if err == nil {
			break
		}
		log.Warn("cannot open the tunnel port, will keep trying", "listen", cfg.Server.Listen, "err", err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Second):
		}
	}
	log.Info("server is up", "listen", cfg.Server.Listen)
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	if err := s.Serve(l, cert); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

func runRelay(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	started := time.Now().Unix()
	var (
		mu       sync.Mutex
		r        = cfg.Relay
		client   *tunnel.Client
		cancelW  context.CancelFunc
		mgr      *relay.Manager
		lastMod  time.Time
		lastSeen = func() time.Time {
			if fi, err := os.Stat(cfg.Path()); err == nil {
				return fi.ModTime()
			}
			return time.Time{}
		}
	)
	connect := func(r *config.Relay) {
		if cancelW != nil {
			cancelW()
			old := client
			// Streams already open on the old tunnel finish on their own.
			time.AfterFunc(time.Minute, old.Close)
		}
		client = tunnel.NewClient(r.Server, r.Fingerprint, r.Secret, r.SNI, r.Conns, log)
		var wctx context.Context
		wctx, cancelW = context.WithCancel(ctx)
		go client.Watch(wctx)
		if mgr != nil {
			mgr.SetDialer(client)
		}
	}
	connect(r)
	mgr = relay.New(client, log)
	mgr.Apply(r.Ports)
	lastMod = lastSeen()

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
		if nr.Server != r.Server || nr.Fingerprint != r.Fingerprint || nr.Secret != r.Secret || nr.SNI != r.SNI || nr.Conns != r.Conns {
			log.Info("tunnel settings changed, reconnecting", "server", nr.Server)
			connect(nr)
		}
		mgr.Apply(nr.Ports)
		r = nr
		lastMod = lastSeen()
		return nil
	}

	go func() {
		err := ctl.Serve(ctx, func() ctl.Status {
			mu.Lock()
			defer mu.Unlock()
			return ctl.Status{Role: config.RoleRelay, Version: buildinfo.Version, Started: started, Target: r.Server, Conns: client.Status(), Ports: mgr.Status()}
		}, reload)
		if err != nil {
			log.Warn("control socket unavailable", "err", err)
		}
	}()
	log.Info("relay is up", "server", r.Server, "ports", len(r.Ports))

	// Edits made by hand are picked up too, a moment after the file changes.
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			mgr.Close()
			return nil
		case <-t.C:
			mu.Lock()
			changed := !lastSeen().Equal(lastMod)
			mu.Unlock()
			if changed {
				if err := reload(); err != nil {
					log.Warn("could not read the changed configuration; keeping the old one", "err", err)
					mu.Lock()
					lastMod = lastSeen()
					mu.Unlock()
				}
			}
		}
	}
}
