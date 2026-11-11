package cli

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/amor7/pol/internal/certs"
	"github.com/amor7/pol/internal/config"
	"github.com/amor7/pol/internal/ctl"
	"github.com/amor7/pol/internal/token"
)

// cloudflarePorts are the HTTPS ports Cloudflare will proxy.
var cloudflarePorts = map[int]bool{443: true, 2053: true, 2083: true, 2087: true, 2096: true, 8443: true}

// ---------------------------------------------------------------- reverse (relay)

// cmdReverse sets up the relay's end of reverse mode and prints the line
// to run on the server: pol reverse [--port N] [--ip A] | pol reverse off
func cmdReverse(path string, a []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	cfg, err := loadRelay(path)
	if err != nil {
		return err
	}
	r := cfg.Relay
	o := parseOpts(a)
	if len(o.pos) > 0 && o.pos[0] == "off" {
		if r.Reverse == nil {
			info("reverse mode is not set up")
			return nil
		}
		_, p, _ := net.SplitHostPort(r.Reverse.Listen)
		n, _ := strconv.Atoi(p)
		addr := net.JoinHostPort(r.Reverse.PublicIP, p)
		r.Reverse = nil
		if err := cfg.Save(); err != nil {
			return err
		}
		closePorts([]int{n})
		if err := apply(); err != nil {
			return err
		}
		okf("reverse mode is off")
		info("on the server, run `pol unlink %s`", addr)
		return nil
	}

	rv := &config.Reverse{}
	if r.Reverse != nil {
		*rv = *r.Reverse
	}
	ours := func(n int) bool { return r.Reverse != nil && r.Reverse.Listen == ":"+strconv.Itoa(n) }
	port := 0
	if v := o.flags["port"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("%q is not a port", v)
		}
		port = n
	} else if r.Reverse != nil {
		_, p, _ := net.SplitHostPort(r.Reverse.Listen)
		port, _ = strconv.Atoi(p)
	} else {
		for _, c := range []int{8444, 2444, 9444, 4443, 10444} {
			if portFree(c) {
				port = c
				break
			}
		}
	}
	if !portFree(port) && !ours(port) {
		return fmt.Errorf("port %d is in use here - choose another with `pol reverse --port N`", port)
	}
	for _, f := range r.Ports {
		if f.Listen == port && !f.UDP() {
			return fmt.Errorf("port %d is one of your forwarded ports - choose another with `pol reverse --port N`", port)
		}
	}
	rv.Listen = ":" + strconv.Itoa(port)
	if v := o.flags["ip"]; v != "" {
		rv.PublicIP = v
	} else if rv.PublicIP == "" {
		info("finding this machine's public address...")
		echo, iface := publicIPv4()
		rv.PublicIP = iface
		if rv.PublicIP == "" {
			rv.PublicIP = echo
		}
		if echo != "" && iface != "" && echo != iface {
			warnf("the outside world sees %s, but this machine's interface has %s", bold(echo), bold(iface))
			if isTerminal() {
				rv.PublicIP = ask("Address the server should connect to:", rv.PublicIP)
			}
		}
	}
	if net.ParseIP(rv.PublicIP) == nil {
		return fmt.Errorf("%q is not an IP address - pass it with --ip", rv.PublicIP)
	}
	cert, err := certs.Load(cfg.Dir())
	if err != nil {
		return err
	}
	r.Reverse = rv
	if err := cfg.Save(); err != nil {
		return err
	}
	openPorts([]int{port})
	if err := apply(); err != nil {
		return err
	}
	okf("reverse mode listening on %s", rv.Listen)
	tok := token.LinkToken{Addr: net.JoinHostPort(rv.PublicIP, strconv.Itoa(port)), Fingerprint: certs.Fingerprint(cert), Secret: r.Secret, SNI: r.SNI}
	fmt.Println()
	fmt.Println("   " + bold("On the abroad server, run this one line:"))
	fmt.Println()
	fmt.Println("pol link " + tok.String())
	fmt.Println()
	fmt.Println("   " + dim("Then switch ports to it with `pol mode <port> reverse`. If this server's provider has a"))
	fmt.Println("   " + dim("firewall in its panel, open TCP "+strconv.Itoa(port)+" there."))
	fmt.Println()
	return nil
}

// ---------------------------------------------------------------- link (server)

func loadServer(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if cfg.Role != config.RoleServer {
		return nil, errors.New("run this on the server (abroad)")
	}
	return cfg, nil
}

// cmdLink makes the server keep reverse connections to a relay.
func cmdLink(path string, a []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if len(a) == 0 {
		return errors.New("usage: pol link <token from `pol reverse` on the relay>")
	}
	cfg, err := loadServer(path)
	if err != nil {
		return err
	}
	tok, err := token.ParseLink(a[0])
	if err != nil {
		return err
	}
	if tok.Secret != cfg.Server.Secret {
		return errors.New("that relay was set up with another server's token - give it this server's token (`pol token`) first")
	}
	l := config.Link{Addr: tok.Addr, Fingerprint: tok.Fingerprint, SNI: tok.SNI}
	s := cfg.Server
	replaced := false
	for i, x := range s.Links {
		if x.Addr == l.Addr {
			s.Links[i] = l
			replaced = true
		}
	}
	if !replaced {
		s.Links = append(s.Links, l)
	}
	if err := cfg.Save(); err != nil {
		return err
	}
	if err := apply(); err != nil {
		return err
	}
	info("connecting to the relay at %s ...", l.Addr)
	for range 20 {
		time.Sleep(300 * time.Millisecond)
		st, err := ctl.Get()
		if err != nil || st.Server == nil {
			break
		}
		for _, x := range st.Server.Links {
			if x.Addr != l.Addr {
				continue
			}
			if x.Up {
				okf("linked - the relay can now use reverse mode (`pol mode <port> reverse` there)")
				return nil
			}
			if x.Err != "" {
				warnf("not connected yet: %s", x.Err)
				info("pol keeps trying; `pol status` shows when it is up")
				return nil
			}
		}
	}
	info("saved - pol keeps trying; `pol status` shows when the link is up")
	return nil
}

func cmdUnlink(path string, a []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if len(a) == 0 {
		return errors.New("usage: pol unlink <relay address> | all")
	}
	cfg, err := loadServer(path)
	if err != nil {
		return err
	}
	s := cfg.Server
	var keep []config.Link
	for _, l := range s.Links {
		if a[0] != "all" && l.Addr != a[0] {
			keep = append(keep, l)
		}
	}
	if len(keep) == len(s.Links) {
		warnf("no link to %s", a[0])
		return nil
	}
	s.Links = keep
	if err := cfg.Save(); err != nil {
		return err
	}
	okf("unlinked")
	return apply()
}

// ---------------------------------------------------------------- cdn (relay)

// cmdCDN sends the ws mode through a CDN: pol cdn <domain> [--ip A] [--port N] | off
func cmdCDN(path string, a []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	cfg, err := loadRelay(path)
	if err != nil {
		return err
	}
	r := cfg.Relay
	o := parseOpts(a)
	if len(o.pos) == 0 {
		if r.CDN == nil {
			info("ws mode goes straight to the server. To send it through Cloudflare: pol cdn <your domain>")
		} else {
			info("ws mode goes through %s", bold(r.CDN.Host))
		}
		return nil
	}
	if o.pos[0] == "off" {
		r.CDN = nil
		if err := cfg.Save(); err != nil {
			return err
		}
		okf("ws and xhttp go straight to the server again")
		return apply()
	}
	_, sp, _ := net.SplitHostPort(r.Server)
	serverPort, _ := strconv.Atoi(sp)
	c := &config.CDN{Host: o.pos[0], Addr: o.flags["ip"]}
	c.Port = serverPort
	if v := o.flags["port"]; v != "" {
		c.Port, _ = strconv.Atoi(v)
	}
	r.CDN = c
	if err := cfg.Save(); err != nil {
		return err
	}
	if err := apply(); err != nil {
		return err
	}
	okf("ws and xhttp now go through %s", bold(c.Host))
	lines := []string{
		bold("In Cloudflare:"),
		"1. DNS: an A record " + c.Host + " → the server's IP, proxied (orange cloud)",
		"2. SSL/TLS: mode " + bold("Full") + " (not Full strict - the server's certificate is its own)",
		"3. Network: WebSockets on (it is by default)",
	}
	if !cloudflarePorts[serverPort] {
		lines = append(lines, "", yellow(fmt.Sprintf("The server's tunnel port %d is not one Cloudflare proxies", serverPort)),
			yellow("(443, 2053, 2083, 2087, 2096, 8443). Set it up again on one of those:"),
			yellow("`pol setup server --port 8443` there, then the new token here."))
	}
	lines = append(lines, "", dim("Then put ports on it: `pol mode <port> ws` (or xhttp). `pol speedtest --mode ws` checks it works."))
	box("CDN for ws and xhttp", lines)
	return nil
}
