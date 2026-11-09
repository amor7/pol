package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/amor7/pol/internal/certs"
	"github.com/amor7/pol/internal/config"
	"github.com/amor7/pol/internal/token"
	"github.com/amor7/pol/internal/tunnel"
)

const installCmd = "bash <(curl -fsSL https://raw.githubusercontent.com/amor7/pol/main/install.sh)"

// opts reads --name value and --name=value; everything else is positional.
type opts struct {
	pos   []string
	flags map[string]string
}

func parseOpts(a []string) opts {
	o := opts{flags: map[string]string{}}
	for i := 0; i < len(a); i++ {
		s := a[i]
		if !strings.HasPrefix(s, "--") {
			o.pos = append(o.pos, s)
			continue
		}
		k, v, has := strings.Cut(strings.TrimPrefix(s, "--"), "=")
		if !has && i+1 < len(a) && !strings.HasPrefix(a[i+1], "--") {
			v = a[i+1]
			i++
		}
		o.flags[k] = v
	}
	return o
}

func cmdSetup(path string, a []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	o := parseOpts(a)
	old, _ := config.Load(path)
	role := ""
	if len(o.pos) > 0 {
		role = o.pos[0]
	}
	if role == "" {
		if old != nil {
			fmt.Println()
			warnf("pol is already set up here as the %s.", bold(old.Role))
			if !confirm("Set it up again?", false) {
				return nil
			}
		}
		fmt.Println()
		fmt.Println("   " + bold("Which server is this?"))
		fmt.Println("   1) " + bold("Abroad") + " - the server your services (x-ui, ...) run on")
		fmt.Println("   2) " + bold("Iran") + "   - the relay users connect to")
		switch ask("Choose 1 or 2:", "") {
		case "1":
			role = config.RoleServer
		case "2":
			role = config.RoleRelay
		default:
			return errors.New("choose 1 or 2")
		}
	}
	switch role {
	case config.RoleServer, "abroad", "kharej", "foreign":
		return setupServer(path, old, o)
	case config.RoleRelay, "iran", "client":
		return setupRelay(path, old, o)
	}
	return fmt.Errorf("unknown role %q - use `pol setup server` or `pol setup relay <token>`", role)
}

func setupServer(path string, old *config.Config, o opts) error {
	interactive := len(o.pos) == 0
	cfg := config.New(path)
	s := &config.Server{SNI: "example.com"}
	if old != nil && old.Server != nil {
		*s = *old.Server // reconfiguring keeps the secret, so relays stay connected
	}
	if v := o.flags["sni"]; v != "" {
		s.SNI = v
	}

	// The tunnel port: 443 looks most like ordinary HTTPS, but on a server
	// that already runs a web panel or x-ui it is usually taken.
	ours := func(n int) bool { return old != nil && old.Server != nil && old.Server.Listen == ":"+strconv.Itoa(n) }
	port := 0
	if v := o.flags["port"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("%q is not a port", v)
		}
		port = n
	} else {
		for _, c := range []int{443, 8443, 2443, 9443, 10443, 20443} {
			if portFree(c) || ours(c) {
				port = c
				break
			}
		}
		if interactive {
			n, err := strconv.Atoi(ask("Tunnel port:", strconv.Itoa(port)))
			if err != nil || n < 1 || n > 65535 {
				return errors.New("that is not a port")
			}
			port = n
		}
	}
	if !portFree(port) && !ours(port) {
		who := whoHolds(port)
		if who != "" {
			who = " (" + who + ")"
		}
		return fmt.Errorf("port %d is already in use on this machine%s - choose another with `pol setup server --port N`", port, who)
	}
	s.Listen = ":" + strconv.Itoa(port)

	if v := o.flags["ip"]; v != "" {
		s.PublicIP = v
	} else {
		info("finding this machine's public address...")
		echo, iface := publicIPv4()
		s.PublicIP = echo
		if echo == "" {
			s.PublicIP = iface
		}
		if interactive {
			if echo != "" && iface != "" && echo != iface {
				warnf("the outside world sees %s, but this machine's interface has %s", bold(echo), bold(iface))
			}
			s.PublicIP = ask("Public IPv4 address relays will connect to:", s.PublicIP)
		}
	}
	if net.ParseIP(s.PublicIP) == nil {
		return fmt.Errorf("%q is not an IP address - pass it with --ip", s.PublicIP)
	}
	if s.Secret == "" {
		b := make([]byte, 24)
		_, _ = rand.Read(b)
		s.Secret = hex.EncodeToString(b)
	}
	cfg.Role = config.RoleServer
	cfg.Server = s
	cert, err := certs.Load(cfg.Dir())
	if err != nil {
		return err
	}
	if err := cfg.Save(); err != nil {
		return err
	}
	okf("configuration saved")
	if started, err := installService(); err != nil {
		return err
	} else if started {
		if err := waitRunning(); err != nil {
			return err
		}
		okf("service started")
	}
	openPorts([]int{port})
	openUDP([]int{port}) // quic mode

	tok := token.Token{Server: net.JoinHostPort(s.PublicIP, strconv.Itoa(port)), Fingerprint: certs.Fingerprint(cert), Secret: s.Secret, SNI: s.SNI}
	box("Server is ready", []string{
		"tunnel   " + cyan(tok.Server),
		"",
		dim("If your provider has a firewall in its panel, open TCP and UDP " + strconv.Itoa(port) + " there."),
		dim("`pol token` prints the token again whenever you need it."),
		dim("Type `pol` any time for the menu."),
	})
	fmt.Println()
	fmt.Println("   " + bold("On the Iran server, run this one line:"))
	fmt.Println()
	fmt.Println(installCmd + " relay " + tok.String() + " --ports 2088")
	fmt.Println()
	fmt.Println("   " + dim("Change --ports to the ports you want (2088,8443 or 2080-2085), or leave it out and use `pol add` later."))
	fmt.Println()
	return nil
}

func setupRelay(path string, old *config.Config, o opts) error {
	raw := o.flags["token"]
	if raw == "" && len(o.pos) > 1 {
		raw = o.pos[1]
	}
	interactive := raw == ""
	if interactive {
		fmt.Println()
		raw = ask("Paste the token the server printed (pol1_...):", "")
	}
	tok, err := token.Parse(raw)
	if err != nil {
		return err
	}

	r := &config.Relay{Server: tok.Server, Fingerprint: tok.Fingerprint, Secret: tok.Secret, SNI: tok.SNI, Conns: 2}
	if old != nil && old.Relay != nil {
		r.Ports = old.Relay.Ports // a new token keeps the ports
		r.Conns = old.Relay.Conns
	}
	if v := o.flags["conns"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 16 {
			return errors.New("--conns takes 1 to 16")
		}
		r.Conns = n
	}
	spec := o.flags["ports"]
	if spec == "" && interactive {
		spec = ask("Ports to forward (e.g. 2088 or 2088,8443 - empty for none yet):", "")
	}
	mode := o.flags["mode"]
	if mode == "" {
		mode = config.DefaultMode
	}
	if !config.ValidMode(mode) {
		return fmt.Errorf("unknown mode %q - use %s", mode, strings.Join(config.Modes, ", "))
	}
	if spec != "" {
		fs, err := config.ParseForwards([]string{spec})
		if err != nil {
			return err
		}
		for _, f := range fs {
			f.Mode = mode
			if i, ok := r.Find(f.Listen, f.ProtoName()); ok {
				r.Ports[i] = f
			} else {
				r.Ports = append(r.Ports, f)
			}
		}
	}

	info("checking the tunnel to %s ...", tok.Server)
	c := tunnel.NewClient(tok.Server, tok.Fingerprint, tok.Secret, tok.SNI, 1, quietLog())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	d, err := c.Ping(ctx)
	cancel()
	c.Close()
	if err != nil {
		warnf("could not reach the server: %v", err)
		warnf("check that TCP %s is open on the server and in its provider's firewall", portOf(tok.Server))
		if interactive && !confirm("Save the setup anyway?", true) {
			return nil
		}
	} else {
		okf("tunnel works - %s round trip", d.Round(time.Millisecond))
	}

	cfg := config.New(path)
	cfg.Role = config.RoleRelay
	cfg.Relay = r
	if err := cfg.Save(); err != nil {
		return err
	}
	okf("configuration saved")
	if started, err := installService(); err != nil {
		return err
	} else if started {
		if err := waitRunning(); err != nil {
			return err
		}
		okf("service started")
	}
	openForwards(r.Ports)

	lines := []string{"server   " + cyan(tok.Server), ""}
	if len(r.Ports) == 0 {
		lines = append(lines, "No ports yet. Add one:  "+bold("pol add 2088"))
	} else {
		lines = append(lines, bold("Forwarded ports"))
		for _, f := range r.Ports {
			lines = append(lines, fmt.Sprintf("  %-10s → %s  %s", f.Key(), f.Target, dim(f.ModeOf()+" mode")))
		}
		lines = append(lines, "", dim("Point your clients at this server's IP with the same ports."))
	}
	lines = append(lines, dim("Type `pol` any time for the menu."))
	box("Relay is ready", lines)
	return nil
}

func portOf(hostport string) string {
	_, p, _ := net.SplitHostPort(hostport)
	return p
}

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
