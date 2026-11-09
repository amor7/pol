// Package config reads and writes /etc/pol/config.json.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// DefaultPath is where the service and the command line look.
const DefaultPath = "/etc/pol/config.json"

// Roles.
const (
	RoleServer = "server" // abroad: where the forwarded services run
	RoleRelay  = "relay"  // Iran: where users connect
)

type Config struct {
	Role   string  `json:"role"`
	Server *Server `json:"server,omitempty"`
	Relay  *Relay  `json:"relay,omitempty"`

	path string
}

// Server is the end the tunnel arrives at.
type Server struct {
	Listen   string `json:"listen"`    // tunnel port, e.g. ":443"
	PublicIP string `json:"public_ip"` // what join tokens point relays at
	Secret   string `json:"secret"`
	SNI      string `json:"sni"` // the server name relays announce
	// AnyTarget lets relays reach other machines, not only this one.
	AnyTarget bool `json:"any_target,omitempty"`
	// NoQUIC stops the server answering quic mode on the tunnel port's
	// number over UDP.
	NoQUIC bool `json:"no_quic,omitempty"`
	// Links are relays the server keeps reverse-mode connections open to.
	Links []Link `json:"links,omitempty"`
}

// Link is a relay to keep reverse connections to (`pol link`).
type Link struct {
	Addr        string `json:"addr"`
	Fingerprint string `json:"fingerprint"`
	SNI         string `json:"sni,omitempty"`
}

// Relay is the end users connect to.
type Relay struct {
	Server      string    `json:"server"` // host:port of the tunnel
	Fingerprint string    `json:"fingerprint"`
	Secret      string    `json:"secret"`
	SNI         string    `json:"sni"`
	Conns       int       `json:"conns"` // parallel tunnel connections
	Ports       []Forward `json:"ports"`
	// SplitConns is how many connections the split mode spreads each user
	// connection over (default 4).
	SplitConns int `json:"split_conns,omitempty"`
	// CDN, when set, sends the ws mode through a CDN such as Cloudflare.
	CDN *CDN `json:"cdn,omitempty"`
	// Reverse, when set, makes the relay accept the server's reverse-mode
	// connections.
	Reverse *Reverse `json:"reverse,omitempty"`
}

// CDN is the domain a CDN serves the server under, for the ws mode.
type CDN struct {
	Host string `json:"host"`           // the domain, proxied by the CDN to the server
	Addr string `json:"addr,omitempty"` // an IP or name to reach the CDN at; the domain if empty
	Port int    `json:"port,omitempty"` // 443 if empty
}

// Reverse is the relay's side of the reverse mode.
type Reverse struct {
	Listen   string `json:"listen"`    // e.g. ":8444"
	PublicIP string `json:"public_ip"` // what the server connects to
}

// Forward sends what arrives on Listen to Target on the server's side.
type Forward struct {
	Listen int    `json:"listen"`
	Target string `json:"target"` // host:port as the server sees it
	Mode   string `json:"mode,omitempty"`
	Proto  string `json:"proto,omitempty"` // "udp", or empty for TCP
}

// UDP reports whether the forward carries UDP.
func (f Forward) UDP() bool { return f.Proto == "udp" }

// ProtoName is "tcp" or "udp".
func (f Forward) ProtoName() string {
	if f.UDP() {
		return "udp"
	}
	return "tcp"
}

// Key tells forwards apart: a port number can be forwarded for TCP and UDP.
func (f Forward) Key() string { return strconv.Itoa(f.Listen) + "/" + f.ProtoName() }

// Tunnel modes, chosen per port.
const (
	// ModeMux carries every connection as a stream inside a few HTTP/2
	// connections: one HTTPS session from outside, the most discreet.
	ModeMux = "mux"
	// ModeTLS gives every connection its own TLS connection: still
	// encrypted, and much faster on lossy or per-connection-throttled paths.
	ModeTLS = "tls"
	// ModeDirect connects straight to the port on the server with plain
	// TCP: nothing added, fastest, and the service's own encryption is all
	// there is. The port has to be reachable from the relay.
	ModeDirect = "direct"
	// ModeSplit spreads each connection over several TLS connections, so
	// one download moves at several connections' speed.
	ModeSplit = "split"
	// ModeQUIC carries connections as streams of one QUIC connection over
	// UDP: copes with packet loss better than anything over TCP.
	ModeQUIC = "quic"
	// ModeObfs is TCP with an encrypted stream and no TLS handshake: looks
	// like noise from the first byte.
	ModeObfs = "obfs"
	// ModeWS uses a WebSocket per connection, and can go through a CDN such
	// as Cloudflare when the server's address is blocked.
	ModeWS = "ws"
	// ModeReverse has the server connect to the relay instead: for paths
	// where Iran-to-abroad connections are cut but the other way is open.
	ModeReverse = "reverse"
)

// Modes lists the modes in the order menus show them.
var Modes = []string{ModeTLS, ModeSplit, ModeQUIC, ModeMux, ModeObfs, ModeWS, ModeReverse, ModeDirect}

// DefaultMode is what `pol add` uses when no mode is given.
const DefaultMode = ModeTLS

// ModeOf is the forward's mode; ports saved before modes existed are mux.
func (f Forward) ModeOf() string {
	if f.Mode == "" {
		return ModeMux
	}
	return f.Mode
}

// ValidMode reports whether m names a mode.
func ValidMode(m string) bool {
	for _, x := range Modes {
		if x == m {
			return true
		}
	}
	return false
}

// Load reads the file at path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("pol is not set up on this machine yet - run `pol setup`")
		}
		return nil, err
	}
	c := &Config{path: path}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	switch c.Role {
	case RoleServer:
		if c.Server == nil {
			return nil, fmt.Errorf("%s: server section missing", path)
		}
	case RoleRelay:
		if c.Relay == nil {
			return nil, fmt.Errorf("%s: relay section missing", path)
		}
		if c.Relay.Conns <= 0 {
			c.Relay.Conns = 2
		}
	default:
		return nil, fmt.Errorf("%s: unknown role %q", path, c.Role)
	}
	return c, nil
}

// New starts an empty configuration that Save writes to path.
func New(path string) *Config { return &Config{path: path} }

// Path is the file this configuration lives in.
func (c *Config) Path() string { return c.path }

// Dir holds the certificate next to the configuration.
func (c *Config) Dir() string { return filepath.Dir(c.path) }

// Save writes the file atomically, readable by root only (it holds the secret).
func (c *Config) Save() error {
	if c.Relay != nil {
		sort.Slice(c.Relay.Ports, func(i, j int) bool { return c.Relay.Ports[i].Listen < c.Relay.Ports[j].Listen })
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// Find finds the forward listening on n for proto ("tcp" or "udp").
func (r *Relay) Find(n int, proto string) (int, bool) {
	for i, f := range r.Ports {
		if f.Listen == n && f.ProtoName() == proto {
			return i, true
		}
	}
	return 0, false
}

// ParseForwards reads what `pol add` is given:
//
//	2088              port 2088 here to port 2088 on the server
//	2088:443          port 2088 here to port 443 on the server
//	2088:10.0.0.5:443 port 2088 here to another machine the server can reach
//	2080-2085         each port in the range to the same port on the server
//	443/udp           a UDP port (any of the above can end in /udp)
//
// Several can be given at once, separated by spaces or commas.
func ParseForwards(args []string) ([]Forward, error) {
	var out []Forward
	for _, a := range args {
		for _, spec := range strings.FieldsFunc(a, func(r rune) bool { return r == ',' || r == ' ' }) {
			fs, err := parseForward(spec)
			if err != nil {
				return nil, err
			}
			out = append(out, fs...)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no port given")
	}
	return out, nil
}

func parseForward(spec string) ([]Forward, error) {
	proto := ""
	if s, ok := strings.CutSuffix(spec, "/udp"); ok {
		spec, proto = s, "udp"
	} else if s, ok := strings.CutSuffix(spec, "/tcp"); ok {
		spec = s
	}
	fs, err := parsePorts(spec)
	for i := range fs {
		fs[i].Proto = proto
	}
	return fs, err
}

func parsePorts(spec string) ([]Forward, error) {
	listen, target, hasTarget := strings.Cut(spec, ":")
	if lo, hi, isRange := strings.Cut(listen, "-"); isRange {
		if hasTarget {
			return nil, fmt.Errorf("%q: a range forwards each port to the same port; it cannot take a target", spec)
		}
		a, err1 := port(lo)
		b, err2 := port(hi)
		if err1 != nil || err2 != nil || b < a {
			return nil, fmt.Errorf("%q is not a port range", spec)
		}
		if b-a >= 1000 {
			return nil, fmt.Errorf("%q: at most 1000 ports in one range", spec)
		}
		out := make([]Forward, 0, b-a+1)
		for p := a; p <= b; p++ {
			out = append(out, Forward{Listen: p, Target: net.JoinHostPort("127.0.0.1", strconv.Itoa(p))})
		}
		return out, nil
	}
	l, err := port(listen)
	if err != nil {
		return nil, fmt.Errorf("%q: %w", spec, err)
	}
	f := Forward{Listen: l, Target: net.JoinHostPort("127.0.0.1", strconv.Itoa(l))}
	if hasTarget {
		if t, err := port(target); err == nil {
			f.Target = net.JoinHostPort("127.0.0.1", strconv.Itoa(t))
		} else {
			host, p, err := net.SplitHostPort(target)
			if err != nil || host == "" {
				return nil, fmt.Errorf("%q: the target must be a port or host:port", spec)
			}
			if _, err := port(p); err != nil {
				return nil, fmt.Errorf("%q: %w", spec, err)
			}
			f.Target = net.JoinHostPort(host, p)
		}
	}
	return []Forward{f}, nil
}

func port(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("%q is not a port (1-65535)", s)
	}
	return n, nil
}
