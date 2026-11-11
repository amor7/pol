// Package cli is the pol command line.
package cli

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/amor7/pol/internal/buildinfo"
	"github.com/amor7/pol/internal/config"
	"github.com/amor7/pol/internal/daemon"
)

const usage = `pol - forward ports from one server to another through an encrypted tunnel

Usage: pol <command> [arguments]
       pol               a menu of everything below, by number

Setting up
  setup                     interactive setup (asks whether this is the server or the relay)
  setup server [--port N]   set up the abroad server (where your services run)
  setup relay <token> [--ports 2088,8443] [--mode M]
                            set up the relay in Iran with the token the server printed

Ports (on the relay)
  add <port>... [--mode M] [--udp|--both]
                            forward ports:  2088   2088:443   2080-2085   443/udp   2088:10.0.0.5:443
  del <port>...             stop forwarding (2088 = TCP and UDP, 2088/udp = only UDP)
  mode <port>... <M>        change the tunnel mode of forwarded ports (at once)
  list                      the forwarded ports (also: ports, ls)
  modes                     every tunnel mode: what it is for and what it costs

Tunnel modes (M), chosen per port - "pol modes" explains each
  fast      auto  tls (default)  split
  stealth   obfs  camo  mux  ssh
  anti-filter  shield  shield-cdn   (padded: hide traffic patterns too)
  CDN       ws  xhttp
  UDP       quic  kcp  hop  faketcp
  special   reverse  dns  direct
  auto:a,b  auto, choosing only among the modes named

Mode setup
  cdn <domain> | off        relay: send ws and xhttp through Cloudflare under this domain
  camo [site]               both: the website camo borrows (default www.microsoft.com)
  sni [domain] | default    relay: the server name the tunnel's TLS shows (a domain of yours is best)
  reverse [--port N] | off  relay: accept the server's reverse connections; prints the line for the server
  link <token>              server: keep reverse connections to the relay that printed this
  unlink <addr> | all       server: stop that
  dns <domain> | off        both: set up dns mode (server answers, relay asks through a resolver)
  via <token> | off         server: be a middle hop, passing everything on to that server

Everyday
  status                    every mode's state, the ports and their traffic
  speedtest [MB] [--mode M] speed of each mode, both ways, ranked (relay)
  ping                      round-trip time through the tunnel (relay)
  token [--new]             print the join token; --new replaces the secret (server)
  logs [-f] [-e]            service logs (-f follow, -e warnings and errors only)
  restart | start | stop    control the service

Maintenance
  tune                      turn on BBR and larger network buffers (both servers)
  update [--file F]         install the latest release (or a downloaded binary)
  uninstall                 stop and remove pol from this machine
  version                   print the version

The configuration lives in /etc/pol/config.json.
`

// Main runs the command line and returns the process exit code.
func Main(args []string) int {
	fs := flag.NewFlagSet("pol", flag.ContinueOnError)
	cfgPath := fs.String("config", envOr("POL_CONFIG", config.DefaultPath), "config file")
	fs.Usage = func() { fmt.Print(usage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		if !isTerminal() {
			fmt.Print(usage)
			return 0
		}
		rest = []string{"menu"}
	}
	var err error
	switch cmd, a := rest[0], rest[1:]; cmd {
	case "menu":
		err = cmdMenu(*cfgPath)
	case "run":
		err = daemon.Run(*cfgPath)
	case "setup", "install":
		err = cmdSetup(*cfgPath, a)
	case "add":
		err = cmdAdd(*cfgPath, a)
	case "del", "rm", "remove", "delete":
		err = cmdDel(*cfgPath, a)
	case "mode":
		err = cmdMode(*cfgPath, a)
	case "reverse":
		err = cmdReverse(*cfgPath, a)
	case "link":
		err = cmdLink(*cfgPath, a)
	case "unlink":
		err = cmdUnlink(*cfgPath, a)
	case "cdn":
		err = cmdCDN(*cfgPath, a)
	case "camo":
		err = cmdCamo(*cfgPath, a)
	case "sni":
		err = cmdSNI(*cfgPath, a)
	case "dns":
		err = cmdDNS(*cfgPath, a)
	case "via", "hop-to":
		err = cmdVia(*cfgPath, a)
	case "modes":
		err = cmdModes()
	case "list", "ls", "ports":
		err = cmdList(*cfgPath)
	case "status":
		err = cmdStatus(*cfgPath)
	case "ping":
		err = cmdPing(*cfgPath)
	case "speedtest", "speed":
		err = cmdSpeed(*cfgPath, a)
	case "token":
		err = cmdToken(*cfgPath, a)
	case "logs", "log":
		err = cmdLogs(a)
	case "restart", "start", "stop":
		err = cmdService(cmd)
	case "tune":
		err = cmdTune()
	case "update", "upgrade":
		err = cmdUpdate(a)
	case "uninstall":
		err = cmdUninstall(*cfgPath)
	case "version", "--version", "-v":
		fmt.Println("pol", buildinfo.Version, runtime.GOOS+"/"+runtime.GOARCH)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		errf("unknown command %q - run `pol help`", cmd)
		return 2
	}
	if err != nil {
		errf("%v", err)
		return 1
	}
	return 0
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ---------------------------------------------------------------- output

var color = func() bool {
	if os.Getenv("NO_COLOR") != "" || runtime.GOOS == "windows" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

func paint(code, s string) string {
	if !color {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

func bold(s string) string   { return paint("1", s) }
func dim(s string) string    { return paint("2", s) }
func green(s string) string  { return paint("32", s) }
func yellow(s string) string { return paint("33", s) }
func red(s string) string    { return paint("31", s) }
func cyan(s string) string   { return paint("36", s) }

func okf(f string, a ...any)   { fmt.Println("   " + green("✓") + " " + fmt.Sprintf(f, a...)) }
func info(f string, a ...any)  { fmt.Println("   " + dim("·") + " " + fmt.Sprintf(f, a...)) }
func warnf(f string, a ...any) { fmt.Println("   " + yellow("!") + " " + fmt.Sprintf(f, a...)) }
func errf(f string, a ...any)  { fmt.Fprintln(os.Stderr, "   "+red("✗")+" "+fmt.Sprintf(f, a...)) }

// box prints a titled frame around lines.
func box(title string, lines []string) {
	w := len([]rune(title)) + 4
	for _, l := range lines {
		w = max(w, visible(l)+4)
	}
	fmt.Println()
	fmt.Println("╭─ " + bold(title) + " " + strings.Repeat("─", w-len([]rune(title))-3) + "╮")
	for _, l := range lines {
		fmt.Println("│ " + l + strings.Repeat(" ", w-visible(l)-1) + "│")
	}
	fmt.Println("╰" + strings.Repeat("─", w) + "╯")
}

// visible is the printed width of s, colour codes left out.
func visible(s string) int {
	n, esc := 0, false
	for _, r := range s {
		switch {
		case r == '\033':
			esc = true
		case esc:
			if r == 'm' {
				esc = false
			}
		default:
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------- input

var stdin = bufio.NewReader(os.Stdin)

// inputClosed is set once stdin has ended (a dropped SSH session), so the
// menu stops instead of asking forever.
var inputClosed bool

func ask(q, def string) string {
	if def != "" {
		fmt.Printf("   %s %s ", q, dim("["+def+"]"))
	} else {
		fmt.Printf("   %s ", q)
	}
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		inputClosed = true
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func confirm(q string, def bool) bool {
	d := "y/N"
	if def {
		d = "Y/n"
	}
	a := strings.ToLower(ask(q, d))
	switch a {
	case "y", "yes", "بله", "آره":
		return true
	case "n", "no", "نه", "خیر":
		return false
	}
	return def
}

// ---------------------------------------------------------------- numbers

func human(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func mbit(bps float64) string {
	return fmt.Sprintf("%.1f Mbit/s", bps/1e6)
}
