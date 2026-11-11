package cli

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"

	"github.com/amor7/pol/internal/buildinfo"
	"github.com/amor7/pol/internal/config"
	"github.com/amor7/pol/internal/ctl"
)

type item struct {
	label string
	run   func() error
}

// isTerminal reports whether someone is typing at stdin, so plain `pol`
// may open the menu instead of printing the help.
func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// cmdMenu is what plain `pol` opens: the common tasks by number, for
// whoever would rather not remember the commands.
func cmdMenu(path string) error {
	for {
		cfg, _ := config.Load(path)
		items, head := menuFor(path, cfg)
		fmt.Println()
		fmt.Println("   " + bold("pol") + " " + dim(buildinfo.Version) + "  " + head)
		fmt.Println()
		for i, it := range items {
			fmt.Printf("   %s %s\n", cyan(fmt.Sprintf("%2d)", i+1)), it.label)
		}
		fmt.Printf("   %s %s\n", cyan(" 0)"), "Exit")
		fmt.Println()
		choice := ask("Choose:", "")
		if inputClosed {
			fmt.Println()
			return nil
		}
		if choice == "0" || choice == "q" || choice == "" {
			if choice == "" {
				continue
			}
			return nil
		}
		var n int
		if _, err := fmt.Sscan(choice, &n); err != nil || n < 1 || n > len(items) {
			warnf("choose a number from the list")
			continue
		}
		fmt.Println()
		if err := items[n-1].run(); err != nil {
			errf("%v", err)
		}
		if _, err := os.Stat(binPath); err != nil && runtime.GOOS == "linux" {
			return nil // uninstalled
		}
		fmt.Println()
		ask(dim("Press Enter to go back to the menu"), "")
	}
}

func menuFor(path string, cfg *config.Config) ([]item, string) {
	if cfg == nil {
		return []item{
			{"Set up this machine as the " + bold("server") + " (abroad, where your services run)", func() error { return cmdSetup(path, []string{config.RoleServer}) }},
			{"Set up this machine as the " + bold("relay") + " (Iran, where users connect)", func() error { return cmdSetup(path, []string{config.RoleRelay}) }},
		}, yellow("not set up yet")
	}
	state := red("stopped")
	if _, err := ctl.Get(); err == nil {
		state = green("running")
	}
	common := []item{
		{"Logs (live - Ctrl+C to stop)", func() error { return followLogs() }},
		{"Restart", func() error { return cmdService("restart") }},
		{startStopLabel(state), func() error {
			if _, err := ctl.Get(); err == nil {
				return cmdService("stop")
			}
			return cmdService("start")
		}},
		{"Speed up the network (BBR)", cmdTune},
		{"Update pol", func() error { return cmdUpdate(nil) }},
		{"Set up again", func() error { return cmdSetup(path, nil) }},
		{red("Uninstall"), func() error { return cmdUninstall(path) }},
	}
	if cfg.Role == config.RoleServer {
		return append([]item{
			{"Status", func() error { return cmdStatus(path) }},
			{"Show the token for the Iran server", func() error { return cmdToken(path, nil) }},
			{"Make a new token (old relays stop working)", func() error { return cmdToken(path, []string{"--new"}) }},
			{"Reverse mode: link a relay (paste its `pol reverse` token)", func() error {
				t := ask("Token from `pol reverse` on the relay (pol1r_...):", "")
				if strings.TrimSpace(t) == "" {
					return nil
				}
				return cmdLink(path, []string{t})
			}},
			{"Middle hop: pass everything on to another server (pol via)", func() error {
				t := ask("Token of the server behind this one (pol1_..., off to stop):", "")
				if strings.TrimSpace(t) == "" {
					return cmdVia(path, nil)
				}
				return cmdVia(path, []string{t})
			}},
			{"Camo: the website whose TLS is borrowed", func() error {
				site := ask("Website (empty keeps the current one):", "")
				if strings.TrimSpace(site) == "" {
					return cmdCamo(path, nil)
				}
				return cmdCamo(path, []string{site})
			}},
			{"DNS mode (emergency, slow): answer for a domain", func() error {
				d := ask("Domain whose NS points at this server (off to stop):", "")
				if strings.TrimSpace(d) == "" {
					return cmdDNS(path, nil)
				}
				return cmdDNS(path, []string{d})
			}},
			{"Reverse mode: unlink relays", func() error {
				for _, l := range cfg.Server.Links {
					info("linked: %s", l.Addr)
				}
				if len(cfg.Server.Links) == 0 {
					info("no relays linked")
					return nil
				}
				a := ask("Address to unlink (or all):", "")
				if strings.TrimSpace(a) == "" {
					return nil
				}
				return cmdUnlink(path, []string{a})
			}},
		}, common...), "server · " + state
	}
	return append([]item{
		{"Status", func() error { return cmdStatus(path) }},
		{"Add ports", func() error {
			spec := ask("Ports to add (e.g. 2088, 2088:443, 2080-2085, or several with spaces):", "")
			if strings.TrimSpace(spec) == "" {
				return nil
			}
			fmt.Println()
			fmt.Println("   1) TCP   2) UDP   3) both")
			proto := ask("Protocol:", "1")
			mode, ok := askMode()
			if !ok {
				return nil
			}
			args := append(strings.Fields(spec), "--mode", mode)
			switch proto {
			case "2":
				args = append(args, "--udp")
			case "3":
				args = append(args, "--both")
			}
			return cmdAdd(path, args)
		}},
		{"Remove ports", func() error {
			if err := cmdList(path); err != nil {
				return err
			}
			fmt.Println()
			spec := ask("Ports to remove:", "")
			if strings.TrimSpace(spec) == "" {
				return nil
			}
			return cmdDel(path, strings.Fields(spec))
		}},
		{"List ports", func() error { return cmdList(path) }},
		{"Change the tunnel mode of ports", func() error {
			if err := cmdList(path); err != nil {
				return err
			}
			fmt.Println()
			spec := ask("Ports to change:", "")
			if strings.TrimSpace(spec) == "" {
				return nil
			}
			mode, ok := askMode()
			if !ok {
				return nil
			}
			return cmdMode(path, append(strings.Fields(spec), mode))
		}},
		{"Speed test (every mode, ranked)", func() error { return cmdSpeed(path, nil) }},
		{"Ping through the tunnel", func() error { return cmdPing(path) }},
		{"All tunnel modes, what each is for and costs", cmdModes},
		{"Reverse mode: set up (prints a line for the server)", func() error { return cmdReverse(path, nil) }},
		{"Camo: the website whose TLS is borrowed", func() error {
			site := ask("Website (empty keeps the current one):", "")
			if strings.TrimSpace(site) == "" {
				return cmdCamo(path, nil)
			}
			return cmdCamo(path, []string{site})
		}},
		{"DNS mode (emergency, slow): set up", func() error {
			d := ask("Domain whose NS points at the server (off to stop):", "")
			if strings.TrimSpace(d) == "" {
				return nil
			}
			res := ask("A resolver this server can reach:", "8.8.8.8")
			return cmdDNS(path, []string{d, "--resolver", res})
		}},
		{"CDN for ws and xhttp modes (Cloudflare)", func() error {
			cur := ""
			if cfg.Relay.CDN != nil {
				cur = cfg.Relay.CDN.Host
			}
			d := ask("Domain on Cloudflare pointing at the server (off to stop):", cur)
			if strings.TrimSpace(d) == "" {
				return nil
			}
			return cmdCDN(path, []string{d})
		}},
	}, common...), "relay · " + state
}

func startStopLabel(state string) string {
	if strings.Contains(state, "running") {
		return "Stop"
	}
	return "Start"
}

// followLogs shows the live log until Ctrl+C, which ends the log and not
// the menu.
func followLogs() error {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	defer signal.Stop(c)
	_ = cmdLogs([]string{"-f"})
	return nil
}
