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

func cmdAdd(path string, a []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	o := parseOpts(a)
	if len(o.pos) == 0 {
		return errors.New("usage: pol add <port>... [--mode tls|mux|direct]   e.g. pol add 2088   pol add 2088:443   pol add 2080-2085")
	}
	mode := o.flags["mode"]
	if mode != "" && !config.ValidMode(mode) {
		return fmt.Errorf("unknown mode %q - use %s", mode, strings.Join(config.Modes, ", "))
	}
	cfg, err := loadRelay(path)
	if err != nil {
		return err
	}
	fs, err := config.ParseForwards(o.pos)
	if err != nil {
		return err
	}
	r := cfg.Relay
	var added []int
	for _, f := range fs {
		if i, ok := r.Port(f.Listen); ok {
			old := r.Ports[i]
			if mode != "" {
				r.Ports[i].Mode = mode
			}
			r.Ports[i].Target = f.Target
			if r.Ports[i] == old {
				info("port %d already forwards to %s (%s)", f.Listen, f.Target, old.ModeOf())
				continue
			}
			okf("port %d now forwards to %s (%s)", f.Listen, f.Target, r.Ports[i].ModeOf())
			continue
		}
		f.Mode = mode
		if f.Mode == "" {
			f.Mode = config.DefaultMode
		}
		if !portFree(f.Listen) {
			who := whoHolds(f.Listen)
			if who != "" {
				who = " by " + who
			}
			warnf("port %d is in use%s - pol will take it as soon as it is free", f.Listen, who)
		}
		r.Ports = append(r.Ports, f)
		added = append(added, f.Listen)
	}
	if err := cfg.Save(); err != nil {
		return err
	}
	openPorts(added)
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
		return errors.New("usage: pol del <port>...")
	}
	cfg, err := loadRelay(path)
	if err != nil {
		return err
	}
	fs, err := config.ParseForwards(a)
	if err != nil {
		return err
	}
	r := cfg.Relay
	var removed []int
	for _, f := range fs {
		i, ok := r.Port(f.Listen)
		if !ok {
			warnf("port %d is not forwarded", f.Listen)
			continue
		}
		r.Ports = append(r.Ports[:i], r.Ports[i+1:]...)
		removed = append(removed, f.Listen)
	}
	if len(removed) == 0 {
		return nil
	}
	if err := cfg.Save(); err != nil {
		return err
	}
	okf("removed %s", joinInts(removed))
	closePorts(removed)
	return apply()
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

// showPorts waits a moment for the service to open the ports, then says how
// each one is doing.
func showPorts(ports []int) {
	want := map[int]bool{}
	for _, p := range ports {
		want[p] = true
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
			if want[p.Listen] && !p.Open && p.Err == "" {
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
		if !want[p.Listen] {
			continue
		}
		switch {
		case p.Open:
			okf("port %d is open → %s %s", p.Listen, p.Target, dim("("+p.Mode+" mode)"))
		case p.Err != "":
			warnf("port %d is not open yet: %s", p.Listen, p.Err)
		default:
			info("port %d is opening...", p.Listen)
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
		info("the tunnel listens on %s", cfg.Server.Listen)
		return nil
	}
	if len(cfg.Relay.Ports) == 0 {
		fmt.Println()
		info("no ports forwarded yet - add one with `pol add 2088`")
		return nil
	}
	live := map[int]relay.PortStatus{}
	if st, err := ctl.Get(); err == nil {
		for _, p := range st.Ports {
			live[p.Listen] = p
		}
	}
	fmt.Println()
	fmt.Println(portTable(cfg.Relay.Ports, live))
	return nil
}

func portTable(fs []config.Forward, live map[int]relay.PortStatus) string {
	var b strings.Builder
	fmt.Fprintf(&b, "   %s\n", dim(fmt.Sprintf("%-7s %-22s %-7s %-10s %7s %7s %11s %11s", "PORT", "TARGET", "MODE", "STATE", "OPEN", "TOTAL", "UP", "DOWN")))
	for _, f := range fs {
		p, ok := live[f.Listen]
		state := dim("stopped")
		switch {
		case ok && p.Open:
			state = green("open")
		case ok && p.Err != "":
			state = red("blocked")
		case ok:
			state = yellow("opening")
		}
		fmt.Fprintf(&b, "   %-7d %-22s %-7s %s %7d %7d %11s %11s\n", f.Listen, f.Target, f.ModeOf(), state+strings.Repeat(" ", max(0, 10-visible(state))), p.Active, p.Total, human(p.Up), human(p.Down))
		if ok && p.Err != "" {
			fmt.Fprintf(&b, "   %s\n", yellow("        ↳ "+p.Err))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// cmdMode changes the tunnel mode of ports already forwarded:
// pol mode 2088 8443 tls
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
	fs, err := config.ParseForwards(a[:len(a)-1])
	if err != nil {
		return err
	}
	r := cfg.Relay
	var changed []int
	for _, f := range fs {
		i, ok := r.Port(f.Listen)
		if !ok {
			warnf("port %d is not forwarded - add it with `pol add %d --mode %s`", f.Listen, f.Listen, mode)
			continue
		}
		if r.Ports[i].ModeOf() == mode {
			info("port %d is already in %s mode", f.Listen, mode)
			continue
		}
		r.Ports[i].Mode = mode
		changed = append(changed, f.Listen)
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
	okf("%s now in %s mode - new connections use it; open ones finish as they are", joinInts(changed), bold(mode))
	return nil
}
