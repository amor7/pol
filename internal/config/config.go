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
}

// Relay is the end users connect to.
type Relay struct {
	Server      string    `json:"server"` // host:port of the tunnel
	Fingerprint string    `json:"fingerprint"`
	Secret      string    `json:"secret"`
	SNI         string    `json:"sni"`
	Conns       int       `json:"conns"` // parallel tunnel connections
	Ports       []Forward `json:"ports"`
}

// Forward sends what arrives on Listen to Target on the server's side.
type Forward struct {
	Listen int    `json:"listen"`
	Target string `json:"target"` // host:port as the server sees it
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

// Port finds the forward listening on n.
func (r *Relay) Port(n int) (int, bool) {
	for i, f := range r.Ports {
		if f.Listen == n {
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
