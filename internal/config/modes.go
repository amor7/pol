package config

import "strings"

// Tunnel modes, chosen per port.
const (
	ModeTLS     = "tls"
	ModeSplit   = "split"
	ModeQUIC    = "quic"
	ModeMux     = "mux"
	ModeObfs    = "obfs"
	ModeCamo    = "camo"
	ModeWS      = "ws"
	ModeXHTTP   = "xhttp"
	ModeSSH     = "ssh"
	ModeKCP     = "kcp"
	ModeHop     = "hop"
	ModeFakeTCP = "faketcp"
	ModeDNS     = "dns"
	ModeReverse = "reverse"
	ModeDirect  = "direct"
	ModeAuto    = "auto"
	// The shield modes: tls and xhttp with padded streams.
	ModeShield    = "shield"
	ModeShieldCDN = "shield-cdn"
)

// Group is what a mode is for, as menus and docs sort them.
type Group string

const (
	GroupFast    Group = "Fast"        // everyday speed
	GroupStealth Group = "Stealth"     // hard to recognise or block
	GroupShield  Group = "Anti-filter" // hide traffic patterns too
	GroupCDN     Group = "CDN"         // through Cloudflare or another CDN
	GroupUDP     Group = "UDP"         // for packet loss, gaming, UDP throttling
	GroupSpecial Group = "Special"     // for particular situations
)

// Groups in the order they are shown.
var Groups = []Group{GroupFast, GroupStealth, GroupShield, GroupCDN, GroupUDP, GroupSpecial}

// Tags, short enough for a menu line.
const (
	TagDownload = "high-speed download"
	TagUpload   = "high-speed upload"
	TagGaming   = "low ping / gaming"
	TagLossy    = "lossy networks"
	TagStealth  = "hard to detect"
	TagCDN      = "works through a CDN"
	TagUDPBlock = "gets past UDP throttling"
	TagIPBlock  = "server IP blocked"
	TagEmerg    = "emergency only"
	TagShort    = "many short connections: web, apps"
	TagBig      = "big downloads"
	TagPattern  = "hides traffic patterns"
)

// Info describes a mode for the people choosing one.
type Info struct {
	Mode  string
	Group Group
	About string // one line: how it travels
	Tags  []string
	// Overhead is the traffic a mode adds to the user's own, measured with
	// TestOverhead on a clean link: framing, encryption, spare FEC data and
	// acknowledgements. Packet headers (a few % for every mode) and resends
	// on a lossy path come on top.
	Overhead string
	Needs    string // what it needs beyond the tunnel port, if anything
	// PerConn is the extra bytes to open one connection (handshakes and
	// setup): it is what matters for web pages and apps, which open many
	// short ones. Idle is what keeping the mode ready costs a day with
	// nobody on it - only while a port uses the mode. Both measured with
	// TestCostProbe.
	PerConn string
	Idle    string
}

// Cost is all three costs on one line.
func (in Info) Cost() string {
	if in.PerConn == "" && in.Idle == "" {
		return in.Overhead
	}
	parts := []string{in.Overhead + " on transfers"}
	if in.PerConn != "" {
		parts = append(parts, in.PerConn+" per connection")
	}
	if in.Idle != "" {
		parts = append(parts, in.Idle+" a day idle")
	}
	return strings.Join(parts, ", ")
}

// Infos is every mode, in the order menus show them.
var Infos = []Info{
	{ModeAuto, GroupFast, "picks the best working mode by itself and switches when one fails", []string{"no babysitting"}, "about 100 MB a day for its checks, plus the chosen mode's costs", "", "", ""},
	{ModeTLS, GroupFast, "a TLS connection per user connection", []string{TagDownload, TagUpload}, "+1%", "", "+4 kB", "14 MB"},
	{ModeSplit, GroupFast, "each user connection spread over 4 TLS connections", []string{TagDownload, TagUpload, TagBig, "beats per-connection throttling"}, "+1%", "", "+16 kB", "15 MB"},
	{ModeObfs, GroupStealth, "encrypted TCP with no TLS handshake: looks like noise", []string{TagDownload, TagStealth, TagShort}, "under +1%", "", "+0.2 kB", "2.5 MB"},
	{ModeCamo, GroupStealth, "borrows a real website's TLS (www.microsoft.com); probers get the real site", []string{TagStealth, "strongest against probing"}, "+1%", "", "+4 kB or more (the site's certificates)", "7 MB"},
	{ModeMux, GroupStealth, "everything inside a few HTTP/2 connections: one HTTPS session from outside", []string{TagStealth, TagShort}, "+1%", "", "+0.2 kB", "24 MB"},
	{ModeSSH, GroupStealth, "one real SSH connection, a channel per user connection: looks like server admin", []string{TagStealth, TagShort}, "+1%", "", "+0.4 kB", "1.5 MB"},
	{ModeShield, GroupShield, "tls with padded packets: the first sizes of each connection no longer show the user's own TLS inside", []string{TagStealth, TagPattern, TagDownload}, "+1%", "", "+4.5 kB", "tls's 14 MB"},
	{ModeShieldCDN, GroupShield, "xhttp with the same padding; works through a CDN", []string{TagStealth, TagPattern, TagCDN, TagIPBlock}, "+1-2%", "a CDN domain for the IP-blocked case (pol cdn)", "+0.7 kB", "xhttp's 2 MB"},
	{ModeWS, GroupCDN, "a WebSocket per user connection", []string{TagCDN, TagIPBlock}, "+1%", "a CDN domain for the IP-blocked case (pol cdn)", "+4.5 kB", "9 MB"},
	{ModeXHTTP, GroupCDN, "plain HTTP requests: one long GET down, POSTs up", []string{TagCDN, TagIPBlock, "looks like web browsing"}, "+1%", "a CDN domain for the IP-blocked case (pol cdn)", "+0.5 kB", "2 MB"},
	{ModeQUIC, GroupUDP, "streams of one QUIC connection over UDP", []string{TagLossy, TagGaming}, "+3%", "UDP on the tunnel port", "+0.7 kB", "5 MB"},
	{ModeKCP, GroupUDP, "KCP over UDP, lost packets rebuilt from spare data", []string{TagGaming, TagLossy}, "+45-75%", "UDP tunnel port + 1", "+6 kB", "8 MB"},
	{ModeHop, GroupUDP, "KCP over UDP, changing port every 30 seconds", []string{TagGaming, TagUDPBlock}, "+45-75%", "UDP tunnel port + 10 to + 29", "about +6 kB", "about 8 MB"},
	{ModeFakeTCP, GroupUDP, "KCP packets dressed as TCP", []string{TagGaming, TagUDPBlock}, "+40-70%", "TCP tunnel port + 2, Linux and iptables on both ends", "about +6 kB", "about 8 MB"},
	{ModeReverse, GroupSpecial, "the server connects to the relay instead", []string{"Iran-to-abroad connections cut"}, "+1%", "pol reverse on the relay, pol link on the server", "+0.2 kB", "about 15 MB"},
	{ModeDNS, GroupSpecial, "data inside DNS lookups, through any resolver", []string{TagEmerg, "only DNS gets out"}, "+130% down, +550% up, very slow", "a domain whose NS points at the server (pol dns)", "large", "about 15 MB"},
	{ModeDirect, GroupSpecial, "plain TCP/UDP straight to the port abroad, no tunnel", []string{"fastest", "nothing added"}, "0%", "the port open to the internet on the server", "0", "0"},
}

// Modes lists the modes in the order menus show them.
var Modes = func() []string {
	out := make([]string, len(Infos))
	for i, in := range Infos {
		out[i] = in.Mode
	}
	return out
}()

// DefaultMode is what `pol add` uses when no mode is given.
const DefaultMode = ModeTLS

// InfoOf describes a mode ("auto:..." included).
func InfoOf(mode string) Info {
	base, _, _ := strings.Cut(mode, ":")
	for _, in := range Infos {
		if in.Mode == base {
			return in
		}
	}
	return Info{Mode: mode}
}

// Label is a mode with its tags and traffic, for one menu line.
func (in Info) Label() string {
	return in.Mode + " - " + in.About + " [" + strings.Join(in.Tags, ", ") + "] (" + in.Cost() + ")"
}

// ModeOf is the forward's mode; ports saved before modes existed are mux.
func (f Forward) ModeOf() string {
	if f.Mode == "" {
		return ModeMux
	}
	return f.Mode
}

// AutoModes is the candidates of an auto spec: "auto" is every mode worth
// trying; "auto:split,tls,ws" those, in that order of preference.
func AutoModes(spec string) []string {
	if _, list, ok := strings.Cut(spec, ":"); ok && list != "" {
		var out []string
		for _, m := range strings.Split(list, ",") {
			if m = strings.TrimSpace(m); m != "" {
				out = append(out, m)
			}
		}
		return out
	}
	// Not dns (too slow to carry users), direct (nothing to check) or
	// auto itself. faketcp, reverse and ws through a CDN join only where
	// they are set up - the relay leaves out what it cannot use.
	return []string{ModeSplit, ModeTLS, ModeQUIC, ModeObfs, ModeCamo, ModeMux, ModeShield, ModeXHTTP, ModeWS, ModeSSH, ModeKCP, ModeHop, ModeFakeTCP, ModeReverse}
}

// ValidMode reports whether m names a mode, "auto:a,b" included.
func ValidMode(m string) bool {
	if base, list, ok := strings.Cut(m, ":"); ok {
		if base != ModeAuto || list == "" {
			return false
		}
		for _, x := range AutoModes(m) {
			if x == ModeAuto || x == ModeDirect || !ValidMode(x) {
				return false
			}
		}
		return true
	}
	for _, x := range Modes {
		if x == m {
			return true
		}
	}
	return false
}
