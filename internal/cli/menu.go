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
		}, common...), "server · " + state
	}
	return append([]item{
		{"Status", func() error { return cmdStatus(path) }},
		{"Add ports", func() error {
			spec := ask("Ports to add (e.g. 2088, 2088:443, 2080-2085, or several with spaces):", "")
			if strings.TrimSpace(spec) == "" {
				return nil
			}
			return cmdAdd(path, strings.Fields(spec))
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
		{"Ping through the tunnel", func() error { return cmdPing(path) }},
		{"Speed test", func() error { return cmdSpeed(path, nil) }},
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
