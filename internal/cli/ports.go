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
	if len(a) == 0 {
		return errors.New("usage: pol add <port>...   e.g. pol add 2088   pol add 2088:443   pol add 2080-2085")
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
	var added []int
	for _, f := range fs {
		if i, ok := r.Port(f.Listen); ok {
			if r.Ports[i].Target == f.Target {
				info("port %d already forwards to %s", f.Listen, f.Target)
				continue
			}
			r.Ports[i].Target = f.Target
			okf("port %d now forwards to %s", f.Listen, f.Target)
			continue
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
			okf("port %d is open → %s", p.Listen, p.Target)
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
	fmt.Fprintf(&b, "   %s\n", dim(fmt.Sprintf("%-7s %-22s %-10s %7s %7s %11s %11s", "PORT", "TARGET", "STATE", "OPEN", "TOTAL", "UP", "DOWN")))
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
		fmt.Fprintf(&b, "   %-7d %-22s %-10s %7d %7d %11s %11s\n", f.Listen, f.Target, state+strings.Repeat(" ", max(0, 10-visible(state))), p.Active, p.Total, human(p.Up), human(p.Down))
		if ok && p.Err != "" {
			fmt.Fprintf(&b, "   %s\n", yellow("        ↳ "+p.Err))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}
