package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amor7/pol/internal/buildinfo"
	"github.com/amor7/pol/internal/certs"
	"github.com/amor7/pol/internal/config"
	"github.com/amor7/pol/internal/ctl"
	"github.com/amor7/pol/internal/relay"
	"github.com/amor7/pol/internal/token"
	"github.com/amor7/pol/internal/tunnel"
)

// ---------------------------------------------------------------- status

func cmdStatus(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	st, err := ctl.Get()
	if err != nil {
		box("pol "+cfg.Role, []string{"service  " + red("not running") + dim("  - start it with `pol start`, see why with `pol logs -e`")})
		return nil
	}
	up := time.Since(time.Unix(st.Started, 0)).Round(time.Second)
	lines := []string{"version  " + st.Version + dim("  up "+up.String())}
	if cfg.Role == config.RoleServer {
		s := st.Server
		lines = append(lines, "tunnel   "+cyan(st.Listen))
		if len(s.Relays) == 0 {
			lines = append(lines, "relays   "+yellow("none connected yet"))
		}
		for i, r := range s.Relays {
			label := "relays   "
			if i > 0 {
				label = "         "
			}
			ago := time.Since(time.Unix(r.LastSeen, 0)).Round(time.Second)
			lines = append(lines, label+green(r.IP)+dim(fmt.Sprintf("  %d open, seen %s ago", r.Open, ago)))
		}
		lines = append(lines, fmt.Sprintf("streams  %d open, %d in all", s.Open, s.Total),
			fmt.Sprintf("traffic  %s in, %s out", human(s.Up), human(s.Down)))
		box("pol server", lines)
		return nil
	}

	lines = append(lines, "server   "+cyan(st.Target))
	for i, c := range st.Conns {
		state := green("up") + dim(fmt.Sprintf("  %.0f ms, %d open", c.RTTms, c.Open))
		if !c.Up {
			state = red("down")
			if c.Err != "" {
				state += dim("  " + shorten(c.Err, 60))
			}
		}
		lines = append(lines, fmt.Sprintf("mux %d    %s", i+1, state))
	}
	if t := st.Raw; t != nil {
		state := green("up") + dim(fmt.Sprintf("  %.0f ms handshake, %d open, %d ready", t.RTTms, t.Open, t.Warm))
		if !t.Up {
			state = red("down")
			if t.Err != "" {
				state += dim("  " + shorten(t.Err, 60))
			}
		}
		lines = append(lines, "tls      "+state)
	}
	box("pol relay", lines)
	live := map[int]relay.PortStatus{}
	for _, p := range st.Ports {
		live[p.Listen] = p
	}
	if len(cfg.Relay.Ports) > 0 {
		fmt.Println()
		fmt.Println(portTable(cfg.Relay.Ports, live))
	} else {
		fmt.Println()
		info("no ports forwarded yet - add one with `pol add 2088`")
	}
	return nil
}

func shorten(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// ---------------------------------------------------------------- tests

func relayClient(path string) (*tunnel.Client, *config.Relay, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, nil, err
	}
	if cfg.Role != config.RoleRelay {
		return nil, nil, errors.New("run this on the relay (the Iran server)")
	}
	r := cfg.Relay
	return tunnel.NewClient(r.Server, r.Fingerprint, r.Secret, r.SNI, 1, quietLog()), r, nil
}

func cmdPing(path string) error {
	c, r, err := relayClient(path)
	if err != nil {
		return err
	}
	defer c.Close()
	fmt.Println()
	info("pinging %s through the tunnel", r.Server)
	var best, sum time.Duration
	n := 0
	ms := func(d time.Duration) string { return fmt.Sprintf("%.1f ms", float64(d)/1e6) }
	for i := range 5 {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		d, err := c.Ping(ctx)
		cancel()
		if err != nil {
			warnf("#%d failed: %v", i+1, err)
			continue
		}
		label := ""
		if i == 0 {
			label = dim("  (includes opening the connection)")
		} else {
			sum += d
			if n == 0 || d < best {
				best = d
			}
			n++
		}
		fmt.Printf("   #%d  %s%s\n", i+1, ms(d), label)
		time.Sleep(300 * time.Millisecond)
	}
	if n == 0 {
		return errors.New("the tunnel does not answer")
	}
	okf("best %s, average %s", ms(best), ms(sum/time.Duration(n)))
	return nil
}

// speedStreams is how many connections each mode's test runs at once. A
// phone or a speed test app opens several; one would hide what sets the
// modes apart.
const speedStreams = 4

func cmdSpeed(path string, a []string) error {
	o := parseOpts(a)
	mb := 20
	if len(o.pos) > 0 {
		n, err := strconv.Atoi(o.pos[0])
		if err != nil || n < 1 || n > 200 {
			return errors.New("give a size from 1 to 200 MB")
		}
		mb = n
	}
	modes := []string{config.ModeTLS, config.ModeMux}
	if m := o.flags["mode"]; m != "" {
		if m != config.ModeTLS && m != config.ModeMux {
			return errors.New("the speed test measures the tls and mux modes (direct mode goes straight to your service)")
		}
		modes = []string{m}
	}
	cfg, err := loadRelay(path)
	if err != nil {
		return err
	}
	r := cfg.Relay
	fmt.Println()
	info("%d MB each way, %d connections at once, to %s", mb, speedStreams, r.Server)
	fmt.Println()
	fmt.Printf("   %s\n", dim(fmt.Sprintf("%-8s %16s %16s", "MODE", "DOWNLOAD", "UPLOAD")))
	per := max(1, mb/speedStreams)
	for _, mode := range modes {
		var down, up func(context.Context, int) (int64, error)
		switch mode {
		case config.ModeMux:
			c := tunnel.NewClient(r.Server, r.Fingerprint, r.Secret, r.SNI, r.Conns, quietLog())
			defer c.Close()
			down, up = c.SpeedDown, c.SpeedUp
		default:
			c := tunnel.NewRawClient(r.Server, r.Fingerprint, r.Secret, r.SNI, 0, quietLog())
			down, up = c.SpeedDown, c.SpeedUp
		}
		d, err1 := parallel(down, per)
		u, err2 := parallel(up, per)
		cell := func(v float64, err error) string {
			if err != nil {
				return red(fmt.Sprintf("%16s", "failed"))
			}
			return bold(fmt.Sprintf("%16s", mbit(v)))
		}
		fmt.Printf("   %-8s %s %s\n", mode, cell(d, err1), cell(u, err2))
		for _, err := range []error{err1, err2} {
			if err != nil {
				warnf("%s: %v", mode, err)
				break
			}
		}
	}
	fmt.Println()
	info("direct mode is not measured here: it goes straight to your service, with nothing of pol's in between.")
	return nil
}

// parallel runs f on speedStreams connections at once and returns the
// combined rate in bits per second.
func parallel(f func(context.Context, int) (int64, error), mb int) (float64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		total int64
		first error
	)
	start := time.Now()
	for range speedStreams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := f(ctx, mb)
			mu.Lock()
			total += n
			if err != nil && first == nil {
				first = err
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if first != nil {
		return 0, first
	}
	return float64(total*8) / time.Since(start).Seconds(), nil
}

// ---------------------------------------------------------------- token

func cmdToken(path string, a []string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if cfg.Role != config.RoleServer {
		return errors.New("tokens come from the server (run this on the abroad server)")
	}
	s := cfg.Server
	if len(a) > 0 && (a[0] == "--new" || a[0] == "new") {
		if err := requireRoot(); err != nil {
			return err
		}
		warnf("relays using the current token stop working until they get the new one.")
		if !confirm("Replace the secret?", false) {
			return nil
		}
		b := make([]byte, 24)
		_, _ = rand.Read(b)
		s.Secret = hex.EncodeToString(b)
		if err := cfg.Save(); err != nil {
			return err
		}
		if hasSystemd() {
			if err := run("systemctl", "restart", "pol"); err != nil {
				return err
			}
		}
		okf("new secret in use")
	}
	cert, err := certs.Load(cfg.Dir())
	if err != nil {
		return err
	}
	_, p, _ := net.SplitHostPort(s.Listen)
	tok := token.Token{Server: net.JoinHostPort(s.PublicIP, p), Fingerprint: certs.Fingerprint(cert), Secret: s.Secret, SNI: s.SNI}
	fmt.Println()
	fmt.Println("   " + bold("Token") + dim(" - give it to `pol setup relay` on the Iran server:"))
	fmt.Println()
	fmt.Println("   " + tok.String())
	fmt.Println()
	fmt.Println("   " + dim("Or install and connect in one go on the Iran server:"))
	fmt.Println()
	fmt.Println("   " + installCmd + " relay " + tok.String())
	fmt.Println()
	return nil
}

// ---------------------------------------------------------------- service

func cmdLogs(a []string) error {
	args := []string{"-u", "pol", "--no-hostname", "-o", "cat"}
	follow := false
	for _, x := range a {
		switch x {
		case "-f", "--follow":
			follow = true
		case "-e", "--errors":
			args = append(args, "-p", "warning")
		}
	}
	if follow {
		args = append(args, "-f", "-n", "50")
	} else {
		args = append(args, "-n", "200")
	}
	cmd := exec.Command("journalctl", args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func cmdService(action string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if !hasSystemd() {
		return errors.New("systemd was not found on this machine")
	}
	if err := run("systemctl", action, "pol"); err != nil {
		return err
	}
	switch action {
	case "stop":
		okf("stopped - it starts again at boot; `pol start` brings it back now")
	default:
		if err := waitRunning(); err != nil {
			return err
		}
		okf("%sed", action)
	}
	return nil
}

func waitRunning() error {
	for range 30 {
		if _, err := ctl.Get(); err == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("the service did not come up - see `pol logs -e`")
}

// ---------------------------------------------------------------- tune

const sysctlPath = "/etc/sysctl.d/99-pol.conf"

const sysctlConf = `# Written by pol tune.
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 131072 67108864
net.ipv4.tcp_wmem = 4096 131072 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3
net.core.somaxconn = 8192
`

func cmdTune() error {
	if err := requireRoot(); err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return errors.New("tune is for Linux")
	}
	if err := os.WriteFile(sysctlPath, []byte(sysctlConf), 0o644); err != nil {
		return err
	}
	if err := run("sysctl", "--system"); err != nil {
		return err
	}
	out, _ := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	if strings.TrimSpace(string(out)) == "bbr" {
		okf("BBR is on and network buffers are larger (%s)", sysctlPath)
	} else {
		warnf("settings written to %s, but this kernel did not switch to BBR (it may be too old)", sysctlPath)
	}
	info("do this on both servers; `rm %s && sysctl --system` undoes it", sysctlPath)
	return nil
}

// ---------------------------------------------------------------- update

func cmdUpdate(a []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	var src string
	for i := 0; i < len(a); i++ {
		if a[i] == "--file" && i+1 < len(a) {
			src = a[i+1]
		}
	}
	if src == "" {
		asset := "pol-linux-" + runtime.GOARCH
		base := "https://github.com/" + buildinfo.Repo + "/releases/latest/download/"
		info("downloading %s ...", asset)
		// Next to the installed binary rather than in /tmp, which is often
		// mounted noexec - the new file has to run once before it is trusted.
		tmp, err := os.CreateTemp(filepath.Dir(binPath), ".pol-update-*")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		sum, err := download(base+asset, tmp)
		tmp.Close()
		if err != nil {
			return err
		}
		want, err := fetchChecksum(base+"checksums.txt", asset)
		if err != nil {
			return err
		}
		if sum != want {
			return errors.New("checksum mismatch - the download is damaged or was tampered with; nothing was changed")
		}
		okf("checksum verified")
		src = tmp.Name()
	}
	if err := os.Chmod(src, 0o755); err != nil {
		return err
	}
	out, err := exec.Command(src, "version").Output()
	if err != nil || !strings.HasPrefix(string(out), "pol ") {
		return errors.New("that file is not a working pol binary")
	}
	if strings.Fields(string(out))[1] == buildinfo.Version {
		okf("already up to date (%s)", buildinfo.Version)
		return nil
	}
	info("installing %s", strings.TrimSpace(string(out)))
	if err := copyFile(src, binPath, 0o755); err != nil {
		return err
	}
	if hasSystemd() {
		if _, err := os.Stat(unitPath); err == nil {
			if err := run("systemctl", "restart", "pol"); err != nil {
				return err
			}
			if err := waitRunning(); err != nil {
				return err
			}
		}
	}
	okf("updated; settings and ports are unchanged")
	return nil
}

// ---------------------------------------------------------------- uninstall

func cmdUninstall(path string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	cfg, _ := config.Load(path)
	fmt.Println()
	warnf("this stops pol and removes the service and the binary.")
	if !confirm("Continue?", false) {
		return nil
	}
	if hasSystemd() {
		_ = run("systemctl", "disable", "--now", "pol")
		_ = os.Remove(unitPath)
		_ = run("systemctl", "daemon-reload")
	}
	if cfg != nil {
		var ports []int
		if cfg.Relay != nil {
			for _, f := range cfg.Relay.Ports {
				ports = append(ports, f.Listen)
			}
		}
		if cfg.Server != nil {
			if _, p, err := net.SplitHostPort(cfg.Server.Listen); err == nil {
				n, _ := strconv.Atoi(p)
				ports = append(ports, n)
			}
		}
		closePorts(ports)
	}
	dir := filepath.Dir(path)
	if confirm("Also delete the configuration and certificate ("+dir+")?", false) {
		_ = os.RemoveAll(dir)
		okf("configuration deleted")
	} else {
		info("configuration kept in %s", dir)
	}
	_ = os.Remove(binPath)
	okf("pol is uninstalled")
	return nil
}
