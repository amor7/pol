package cli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	binPath  = "/usr/local/bin/pol"
	unitPath = "/etc/systemd/system/pol.service"
)

const unit = `[Unit]
Description=pol tunnel
Documentation=https://github.com/amor7/pol
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/pol run
Restart=always
RestartSec=2
LimitNOFILE=1048576
RuntimeDirectory=pol
RuntimeDirectoryMode=0700

[Install]
WantedBy=multi-user.target
`

func requireRoot() error {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		return errors.New("run this as root (sudo pol ...)")
	}
	return nil
}

func hasSystemd() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), msg)
	}
	return nil
}

// installService copies this binary into place (when run from elsewhere,
// as the install script does) and starts the service. It reports false
// when there is no service manager to start it with.
func installService() (bool, error) {
	if runtime.GOOS != "linux" {
		warnf("not Linux - start pol yourself with `pol run`")
		return false, nil
	}
	if self, err := os.Executable(); err == nil && self != binPath {
		if err := copyFile(self, binPath, 0o755); err != nil {
			return false, err
		}
	}
	if !hasSystemd() {
		warnf("systemd was not found - start pol yourself with `%s run`", binPath)
		return false, nil
	}
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return false, err
	}
	if err := run("systemctl", "daemon-reload"); err != nil {
		return false, err
	}
	if err := run("systemctl", "enable", "pol"); err != nil {
		return false, err
	}
	return true, run("systemctl", "restart", "pol")
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst) // works while the old binary is running
}

// ---------------------------------------------------------------- firewall

func ufwActive() bool {
	out, err := exec.Command("ufw", "status").Output()
	return err == nil && strings.Contains(string(out), "Status: active")
}

// openPorts lets the ports through ufw when ufw is in charge. Providers'
// own firewalls (in their web panels) are out of reach; setup says so.
func openPorts(ports []int) {
	if len(ports) == 0 || !ufwActive() {
		return
	}
	for _, p := range ports {
		_ = run("ufw", "allow", strconv.Itoa(p)+"/tcp")
	}
	okf("opened in ufw: %s", joinInts(ports))
}

func closePorts(ports []int) {
	if len(ports) == 0 || !ufwActive() {
		return
	}
	for _, p := range ports {
		_ = run("ufw", "delete", "allow", strconv.Itoa(p)+"/tcp")
	}
	info("closed in ufw: %s", joinInts(ports))
}

func joinInts(ns []int) string {
	s := make([]string, len(ns))
	for i, n := range ns {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ", ")
}

// portFree reports whether nothing on this machine listens on TCP port n.
func portFree(n int) bool {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(n))
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// whoHolds names the program on TCP port n, when ss can tell.
func whoHolds(n int) string {
	out, err := exec.Command("ss", "-ltnpH", "sport", "= :"+strconv.Itoa(n)).Output()
	if err != nil {
		return ""
	}
	s := string(out)
	if i := strings.Index(s, `(("`); i >= 0 {
		s = s[i+3:]
		if j := strings.Index(s, `"`); j >= 0 {
			return s[:j]
		}
	}
	return ""
}

// ---------------------------------------------------------------- addresses

// publicIPv4 asks a few echo services, then falls back to the first public
// address on an interface. On networks that send traffic out through
// another address the two differ; setup shows both when they do.
func publicIPv4() (echo, iface string) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp4", addr)
		}},
	}
	for _, u := range []string{"https://api.ipify.org", "https://ipv4.icanhazip.com", "https://ifconfig.me/ip", "https://checkip.amazonaws.com"} {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if a, err := netip.ParseAddr(strings.TrimSpace(string(b))); err == nil && a.Is4() {
			echo = a.String()
			break
		}
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			ip := p.Addr()
			if ip.Is4() && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() {
				iface = ip.String()
				break
			}
		}
	}
	return echo, iface
}

// ---------------------------------------------------------------- downloads

func download(url string, w io.Writer) (string, error) {
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("download failed: %s", resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(w, h), resp.Body); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fetchChecksum(url, asset string) (string, error) {
	resp, err := (&http.Client{Timeout: time.Minute}).Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == asset {
			return f[0], nil
		}
	}
	return "", errors.New("no checksum published for " + asset)
}
