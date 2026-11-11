package cli

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/amor7/pol/internal/config"
	"github.com/amor7/pol/internal/token"
	"github.com/amor7/pol/internal/tunnel"
)

// printModes lists the modes by group, numbered from 1 in that order, with
// what each is for and what it costs in traffic. It returns the modes in the
// order they were numbered.
func printModes(numbered bool) []string {
	var order []string
	n := 0
	for _, g := range config.Groups {
		fmt.Println()
		fmt.Println("   " + bold(string(g)))
		for _, in := range config.Infos {
			if in.Group != g {
				continue
			}
			n++
			order = append(order, in.Mode)
			num := "  "
			if numbered {
				num = cyan(fmt.Sprintf("%2d)", n))
			}
			rec := ""
			if in.Mode == config.DefaultMode {
				rec = green(" (default)")
			}
			fmt.Printf("   %s %-8s %s%s\n", num, bold(in.Mode), in.About, rec)
			fmt.Printf("       %-10s %s  %s\n", "", yellow(strings.Join(in.Tags, " · ")), dim("(traffic: "+in.Cost()+")"))
			if in.Needs != "" {
				fmt.Printf("       %-10s %s\n", "", dim("needs: "+in.Needs))
			}
		}
	}
	return order
}

func cmdModes() error {
	printModes(false)
	fmt.Println()
	info("traffic is what a mode adds to your users' own, measured on a clean link:")
	info("  on transfers - per byte moved; what big downloads cost")
	info("  per connection - to open one; what web pages and apps, with many short connections, cost")
	info("  a day idle - keeping it ready, only while a port uses the mode")
	info("packet headers (a few %% for every mode) and resends on a lossy path come on top.")
	info("`pol speedtest` measures every mode on your own servers.")
	return nil
}

// askMode offers the tunnel modes by number, grouped.
func askMode() (string, bool) {
	fmt.Println()
	fmt.Println("   " + bold("Tunnel mode") + dim("  (`pol speedtest` shows which is fastest on your path)"))
	order := printModes(true)
	fmt.Println()
	def := "1"
	for i, m := range order {
		if m == config.DefaultMode {
			def = strconv.Itoa(i + 1)
		}
	}
	n, err := strconv.Atoi(ask(fmt.Sprintf("Choose 1-%d:", len(order)), def))
	if err != nil || n < 1 || n > len(order) {
		warnf("choose a number from the list")
		return "", false
	}
	return order[n-1], true
}

// ---------------------------------------------------------------- camo

// cmdCamo sets the website camo mode borrows, on either end: pol camo <site>
func cmdCamo(path string, a []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	cfg, err := loadAny(path)
	if err != nil {
		return err
	}
	cur := tunnel.DefaultCamo
	if cfg.Server != nil && cfg.Server.Camo != "" {
		cur = cfg.Server.Camo
	}
	if cfg.Relay != nil && cfg.Relay.Camo != "" {
		cur = cfg.Relay.Camo
	}
	if len(a) == 0 {
		info("camo borrows the TLS of %s", bold(cur))
		info("change it with `pol camo <site>` on both servers - they must match")
		return nil
	}
	site := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(a[0], "https://"), "http://"), "/"))
	if site == "default" {
		site = ""
	}
	if strings.ContainsAny(site, " /:") {
		return errors.New("give a site name like www.microsoft.com")
	}
	if cfg.Server != nil {
		cfg.Server.Camo = site
	} else {
		cfg.Relay.Camo = site
	}
	if err := cfg.Save(); err != nil {
		return err
	}
	shown := site
	if shown == "" {
		shown = tunnel.DefaultCamo
	}
	okf("camo now borrows %s", bold(shown))
	if cfg.Server != nil {
		info("restarting so the server answers for it...")
		if err := cmdService("restart"); err != nil {
			return err
		}
	} else if err := apply(); err != nil {
		return err
	}
	warnf("set the same site on the other server: pol camo %s", shown)
	info("pick a large site that serves TLS 1.3 and is not blocked in Iran")
	return nil
}

// cmdSNI shows or sets the server name the relay's TLS connections show.
func cmdSNI(path string, a []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	cfg, err := loadAny(path)
	if err != nil {
		return err
	}
	if cfg.Relay == nil {
		info("the relay chooses the name its connections show: run `pol sni` there")
		return nil
	}
	r := cfg.Relay
	if len(a) == 0 {
		info("the tunnel's TLS shows the name %s", bold(tunnel.PickSNI(r.SNI, r.Secret, r.Camo)))
		info("change it with `pol sni <domain>`: best a domain of yours whose DNS points at the server abroad")
		info("`pol sni default` goes back to a large site chosen for this relay")
		return nil
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(a[0], "https://"), "http://"), "/"))
	if name == "default" {
		name = ""
	}
	if strings.ContainsAny(name, " /:") || (name != "" && !strings.Contains(name, ".")) {
		return errors.New("give a domain like www.example.org")
	}
	camo := r.Camo
	if camo == "" {
		camo = tunnel.DefaultCamo
	}
	if strings.EqualFold(name, camo) {
		return errors.New("that is camo's site: the server would take these connections for camo mode - pick another")
	}
	r.SNI = name
	if err := cfg.Save(); err != nil {
		return err
	}
	okf("the tunnel's TLS now shows %s", bold(tunnel.PickSNI(r.SNI, r.Secret, r.Camo)))
	return apply()
}

func loadAny(path string) (*config.Config, error) {
	return config.Load(path)
}

// ---------------------------------------------------------------- dns

// cmdDNS sets up dns mode. On the server: pol dns <domain>. On the relay:
// pol dns <domain> [--resolver 8.8.8.8]. pol dns off on either undoes it.
func cmdDNS(path string, a []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	o := parseOpts(a)
	if len(o.pos) == 0 {
		switch {
		case cfg.Server != nil && cfg.Server.DNSDomain != "":
			info("answering dns mode for %s on UDP 53", bold(cfg.Server.DNSDomain))
		case cfg.Relay != nil && cfg.Relay.DNS != nil:
			info("dns mode: %s through %s", bold(cfg.Relay.DNS.Domain), cfg.Relay.DNS.Resolver)
		default:
			info("dns mode is not set up - `pol dns <domain>` on both servers (see `pol help`)")
		}
		return nil
	}
	off := o.pos[0] == "off"
	domain := strings.TrimSuffix(strings.ToLower(o.pos[0]), ".")
	if !off && (strings.Count(domain, ".") < 1 || strings.ContainsAny(domain, " /:")) {
		return errors.New("give a domain like t.yourdomain.com")
	}
	if cfg.Server != nil {
		if off {
			cfg.Server.DNSDomain = ""
		} else {
			if !portFreeUDP(53) {
				warnf("UDP 53 is in use on this machine (systemd-resolved?) - pol keeps trying until it is free")
			}
			cfg.Server.DNSDomain = domain
		}
		if err := cfg.Save(); err != nil {
			return err
		}
		if off {
			closeForwards([]config.Forward{{Listen: 53, Proto: "udp"}})
		} else {
			openUDP([]int{53})
		}
		if err := cmdService("restart"); err != nil {
			return err
		}
		if off {
			okf("dns mode is off")
			return nil
		}
		okf("answering dns mode for %s", bold(domain))
		box("dns mode: at your domain's DNS host", []string{
			"1. an A record   ns." + parentOf(domain) + " → this server's IP",
			"2. an NS record  " + domain + " → ns." + parentOf(domain),
			"",
			"Then on the relay: pol dns " + domain + " --resolver 8.8.8.8",
			dim("Any resolver the relay can reach works, an Iranian one too."),
			dim("dns mode is slow - for emergencies, not for your users' traffic."),
		})
		return nil
	}
	r := cfg.Relay
	if off {
		r.DNS = nil
	} else {
		res := o.flags["resolver"]
		if res == "" && r.DNS != nil {
			res = r.DNS.Resolver
		}
		if res == "" {
			res = "8.8.8.8"
		}
		if net.ParseIP(strings.Trim(strings.Split(res, ":")[0], "[]")) == nil {
			if _, _, err := net.SplitHostPort(res); err != nil {
				return fmt.Errorf("%q is not a resolver address - give an IP like 8.8.8.8", res)
			}
		}
		r.DNS = &config.DNS{Domain: domain, Resolver: res}
	}
	if err := cfg.Save(); err != nil {
		return err
	}
	if err := apply(); err != nil {
		return err
	}
	if off {
		okf("dns mode is off")
		return nil
	}
	okf("dns mode: %s through %s", bold(domain), r.DNS.Resolver)
	info("check it with `pol speedtest --mode dns`, then `pol mode <port> dns` if you need it")
	return nil
}

func parentOf(d string) string {
	if i := strings.Index(d, "."); i >= 0 && strings.Count(d, ".") >= 2 {
		return d[i+1:]
	}
	return d
}

// ---------------------------------------------------------------- via

// cmdVia makes this server a middle hop to another: pol via <token> [--mode M].
func cmdVia(path string, a []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	cfg, err := loadServer(path)
	if err != nil {
		return err
	}
	o := parseOpts(a)
	if len(o.pos) == 0 {
		if cfg.Server.Next == nil {
			info("this server is not a middle hop")
			info("to pass everything on to another pol server: pol via <its token> [--mode tls]")
		} else {
			t, _ := token.Parse(cfg.Server.Next.Token)
			info("middle hop: everything goes on to %s (%s mode)", bold(t.Server), orDefault(cfg.Server.Next.Mode, config.ModeTLS))
		}
		return nil
	}
	if o.pos[0] == "off" {
		cfg.Server.Next = nil
		if err := cfg.Save(); err != nil {
			return err
		}
		okf("no longer a middle hop")
		return cmdService("restart")
	}
	tok, err := token.Parse(o.pos[0])
	if err != nil {
		return err
	}
	mode := o.flags["mode"]
	switch mode {
	case "", config.ModeTLS, config.ModeSplit, config.ModeMux, config.ModeObfs, config.ModeQUIC, config.ModeCamo, config.ModeSSH, config.ModeKCP, config.ModeHop, config.ModeWS, config.ModeXHTTP:
	default:
		return fmt.Errorf("a middle hop can reach the next server with tls, split, mux, obfs, quic, camo, ssh, kcp, hop, ws or xhttp")
	}
	cfg.Server.Next = &config.Next{Token: tok.String(), Mode: mode}
	if err := cfg.Save(); err != nil {
		return err
	}
	okf("middle hop: everything relays send here goes on to %s (%s mode)", bold(tok.Server), orDefault(mode, config.ModeTLS))
	info("the relays keep their token for this server; nothing changes there")
	return cmdService("restart")
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
