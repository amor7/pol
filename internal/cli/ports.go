package cli

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/amor7/pol/internal/config"
	"github.com/amor7/pol/internal/ctl"
	"github.com/amor7/pol/internal/relay"
)

func loadRelay(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if cfg.Role != config.RoleRelay {
		return nil, errors.New("ports are added on the relay (the Iran server); this machine is the server")
	}
	return cfg, nil
}

// forwardsFrom reads port arguments, applying --udp and --both.
func forwardsFrom(o opts) ([]config.Forward, error) {
	fs, err := config.ParseForwards(o.pos)
	if err != nil {
		return nil, err
	}
	_, udp := o.flags["udp"]
	_, both := o.flags["both"]
	if !udp && !both {
		return fs, nil
	}
	var out []config.Forward
	for _, f := range fs {
		if both {
			t := f
			t.Proto = ""
			out = append(out, t)
		}
		f.Proto = "udp"
		out = append(out, f)
	}
	return out, nil
}

func modeFlag(o opts) (string, error) {
	mode := o.flags["mode"]
	if mode != "" && !config.ValidMode(mode) {
		return "", fmt.Errorf("unknown mode %q - use %s", mode, strings.Join(config.Modes, ", "))
	}
	return mode, nil
}

func cmdAdd(path string, a []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	o := parseOpts(a)
	if len(o.pos) == 0 {
		return errors.New("usage: pol add <port>... [--mode M] [--udp|--both]   e.g. pol add 2088   pol add 2088:443   pol add 443/udp --mode quic")
	}
	mode, err := modeFlag(o)
	if err != nil {
		return err
	}
	cfg, err := loadRelay(path)
	if err != nil {
		return err
	}
	fs, err := forwardsFrom(o)
	if err != nil {
		return err
	}
	r := cfg.Relay
	var added []config.Forward
	for _, f := range fs {
		if i, ok := r.Find(f.Listen, f.ProtoName()); ok {
			old := r.Ports[i]
			if mode != "" {
				r.Ports[i].Mode = mode
			}
			r.Ports[i].Target = f.Target
			if r.Ports[i] == old {
				info("%s already forwards to %s (%s)", f.Key(), f.Target, old.ModeOf())
				continue
			}
			okf("%s now forwards to %s (%s)", f.Key(), f.Target, r.Ports[i].ModeOf())
			continue
		}
		f.Mode = mode
		if f.Mode == "" {
			f.Mode = config.DefaultMode
		}
		if !f.UDP() && !portFree(f.Listen) {
			who := whoHolds(f.Listen)
			if who != "" {
				who = " by " + who
			}
			warnf("port %d is in use%s - pol will take it as soon as it is free", f.Listen, who)
		}
		r.Ports = append(r.Ports, f)
		added = append(added, f)
	}
	if err := cfg.Save(); err != nil {
		return err
	}
	openForwards(added)
	if err := apply(); err != nil {
		return err
	}
	if len(added) > 0 {
		showPorts(added)
	}
	return nil
}

func cmdDel(path string, a []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if len(a) == 0 {
		return errors.New("usage: pol del <port>...   (2088 removes TCP and UDP; 2088/udp only UDP)")
	}
	cfg, err := loadRelay(path)
	if err != nil {
		return err
	}
	r := cfg.Relay
	var removed []config.Forward
	for _, arg := range a {
		fs, err := config.ParseForwards([]string{arg})
		if err != nil {
			return err
		}
		only := strings.HasSuffix(arg, "/udp") || strings.HasSuffix(arg, "/tcp")
		for _, f := range fs {
			found := false
			for _, proto := range []string{"tcp", "udp"} {
				if only && proto != f.ProtoName() {
					continue
				}
				if i, ok := r.Find(f.Listen, proto); ok {
					removed = append(removed, r.Ports[i])
					r.Ports = append(r.Ports[:i], r.Ports[i+1:]...)
					found = true
				}
			}
			if !found {
				warnf("%s is not forwarded", f.Key())
			}
		}
	}
	if len(removed) == 0 {
		return nil
	}
	if err := cfg.Save(); err != nil {
		return err
	}
	keys := make([]string, len(removed))
	for i, f := range removed {
		keys[i] = f.Key()
	}
	okf("removed %s", strings.Join(keys, ", "))
	closeForwards(removed)
	return apply()
}

// cmdMode changes the tunnel mode of ports already forwarded:
// pol mode 2088 443/udp quic
func cmdMode(path string, a []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if len(a) < 2 || !config.ValidMode(a[len(a)-1]) {
		return fmt.Errorf("usage: pol mode <port>... <%s>", strings.Join(config.Modes, "|"))
	}
	mode := a[len(a)-1]
	cfg, err := loadRelay(path)
	if err != nil {
		return err
	}
	r := cfg.Relay
	var changed []string
	for _, arg := range a[:len(a)-1] {
		fs, err := config.ParseForwards([]string{arg})
		if err != nil {
			return err
		}
		only := strings.HasSuffix(arg, "/udp") || strings.HasSuffix(arg, "/tcp")
		for _, f := range fs {
			found := false
			for _, proto := range []string{"tcp", "udp"} {
				if only && proto != f.ProtoName() {
					continue
				}
				i, ok := r.Find(f.Listen, proto)
				if !ok {
					continue
				}
				found = true
				if r.Ports[i].ModeOf() == mode {
					info("%s is already in %s mode", r.Ports[i].Key(), mode)
					continue
				}
				r.Ports[i].Mode = mode
				changed = append(changed, r.Ports[i].Key())
			}
			if !found {
				warnf("%s is not forwarded - add it with `pol add %s --mode %s`", f.Key(), arg, mode)
			}
		}
	}
	if len(changed) == 0 {
		return nil
	}
	if err := cfg.Save(); err != nil {
		return err
	}
	if err := apply(); err != nil {
		return err
	}
	okf("%s now in %s mode - its users were reconnected through it at once", strings.Join(changed, ", "), bold(mode))
	modeHints(cfg, mode)
	return nil
}

// modeHints says what a mode still needs.
func modeHints(cfg *config.Config, mode string) {
	switch mode {
	case config.ModeReverse:
		if cfg.Relay.Reverse == nil {
			warnf("reverse mode needs setting up first: `pol reverse`")
		}
	case config.ModeDirect:
		info("direct mode connects straight to the server: the port must be open to the internet there")
	case config.ModeWS:
		if cfg.Relay.CDN == nil {
			info("ws goes straight to the server; `pol cdn <domain>` sends it through Cloudflare instead")
		}
	case config.ModeQUIC:
		info("quic uses UDP on the tunnel port - open it in the server provider's firewall if there is one")
	}
}

// apply asks the running service to pick up the saved configuration.
func apply() error {
	running, err := ctl.Reload()
	if err != nil {
		return err
	}
	if !running {
		warnf("the service is not running - the change applies when it starts (`pol start`)")
	}
	return nil
}

func statusKey(p relay.PortStatus) string { return fmt.Sprintf("%d/%s", p.Listen, p.Proto) }

// showPorts waits a moment for the service to open the ports, then says how
// each one is doing.
func showPorts(fs []config.Forward) {
	want := map[string]bool{}
	for _, f := range fs {
		want[f.Key()] = true
	}
	var st *ctl.Status
	for range 10 {
		time.Sleep(200 * time.Millisecond)
		s, err := ctl.Get()
		if err != nil {
			return
		}
		st = s
		done := true
		for _, p := range s.Ports {
			if want[statusKey(p)] && !p.Open && p.Err == "" {
				done = false
			}
		}
		if done {
			break
		}
	}
	if st == nil {
		return
	}
	for _, p := range st.Ports {
		if !want[statusKey(p)] {
			continue
		}
		switch {
		case p.Open:
			okf("%s is open → %s %s", statusKey(p), p.Target, dim("("+p.Mode+" mode)"))
		case p.Err != "":
			warnf("%s is not open yet: %s", statusKey(p), p.Err)
		default:
			info("%s is opening...", statusKey(p))
		}
	}
}

func cmdList(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if cfg.Role == config.RoleServer {
		fmt.Println()
		info("this is the server; ports are chosen on the relay with `pol add`.")
		info("the tunnel listens on %s (TCP, and UDP for quic mode)", cfg.Server.Listen)
		return nil
	}
	if len(cfg.Relay.Ports) == 0 {
		fmt.Println()
		info("no ports forwarded yet - add one with `pol add 2088`")
		return nil
	}
	live := map[string]relay.PortStatus{}
	if st, err := ctl.Get(); err == nil {
		for _, p := range st.Ports {
			live[statusKey(p)] = p
		}
	}
	fmt.Println()
	fmt.Println(portTable(cfg.Relay.Ports, live))
	return nil
}

func portTable(fs []config.Forward, live map[string]relay.PortStatus) string {
	var b strings.Builder
	fmt.Fprintf(&b, "   %s\n", dim(fmt.Sprintf("%-10s %-22s %-8s %-10s %7s %7s %11s %11s", "PORT", "TARGET", "MODE", "STATE", "OPEN", "TOTAL", "UP", "DOWN")))
	for _, f := range fs {
		p, ok := live[f.Key()]
		state := dim("stopped")
		switch {
		case ok && p.Open:
			state = green("open")
		case ok && p.Err != "":
			state = red("blocked")
		case ok:
			state = yellow("opening")
		}
		name := fmt.Sprint(f.Listen)
		if f.UDP() {
			name += "/udp"
		}
		fmt.Fprintf(&b, "   %-10s %-22s %-8s %s %7d %7d %11s %11s\n", name, f.Target, f.ModeOf(), state+strings.Repeat(" ", max(0, 10-visible(state))), p.Active, p.Total, human(p.Up), human(p.Down))
		if ok && p.Err != "" {
			fmt.Fprintf(&b, "   %s\n", yellow("        ↳ "+p.Err))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}
