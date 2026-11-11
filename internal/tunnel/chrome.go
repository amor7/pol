package tunnel

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Every TLS connection the relay opens to its own server starts the way a
// current Chrome starts one: the same ClientHello, byte for byte, offering
// h2 and http/1.1 like a browser. Nothing in the clear says pol: no
// protocol name of its own, and a server name from PickSNI. The server
// tells pol's own streams from web requests by the first bytes sent
// inside the encryption.
//
// TLS 1.3 is insisted on: it encrypts the server's certificate, which is
// pol's own and would otherwise be seen.

// LegacySNI is the server name earlier versions sent; it is replaced.
const LegacySNI = "example.com"

// sniPool is large sites reachable from Iran, one of which a relay
// names when no server name was set. A domain of your own pointing at the
// server is better still (`pol sni`): then the name and the address agree.
var sniPool = []string{"www.apple.com", "www.bing.com", "www.office.com", "learn.microsoft.com", "www.speedtest.net"}

// PickSNI is the server name to send: sni if one was set, otherwise one
// from sniPool chosen by the secret, so it stays the same for a relay.
// It is never the camo site, which the server would take for camo mode.
func PickSNI(sni, secret, camo string) string {
	if sni != "" && sni != LegacySNI {
		return sni
	}
	h := sha256.Sum256([]byte("pol sni " + secret))
	i := int(h[0]) % len(sniPool)
	for k := range sniPool {
		s := sniPool[(i+k)%len(sniPool)]
		if !strings.EqualFold(s, camo) && !strings.EqualFold(s, DefaultCamo) {
			return s
		}
	}
	return sniPool[i]
}

// chromeDial connects to addr with Chrome's ClientHello, trusting only the
// certificate with this fingerprint. alpn nil offers what Chrome offers
// (h2, http/1.1); otherwise exactly alpn, as Chrome does for a WebSocket.
func chromeDial(ctx context.Context, addr, sni, fingerprint string, alpn []string) (*utls.UConn, error) {
	nd := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	raw, err := nd.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	want := strings.ToLower(fingerprint)
	cfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // replaced by the pin check below
		VerifyPeerCertificate: func(certs [][]byte, _ [][]*x509.Certificate) error {
			if len(certs) == 0 {
				return errors.New("the server presented no certificate")
			}
			s := sha256.Sum256(certs[0])
			if hex.EncodeToString(s[:]) != want {
				return errors.New("the server's certificate is not the one in the token")
			}
			return nil
		},
	}
	var uc *utls.UConn
	if alpn == nil {
		uc = utls.UClient(raw, cfg, utls.HelloChrome_Auto)
	} else {
		spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
		if err != nil {
			raw.Close()
			return nil, err
		}
		h2 := slices.Contains(alpn, "h2")
		exts := spec.Extensions[:0]
		for _, e := range spec.Extensions {
			switch x := e.(type) {
			case *utls.ALPNExtension:
				x.AlpnProtocols = alpn
			case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew:
				if !h2 { // ALPS only goes with h2
					continue
				}
			}
			exts = append(exts, e)
		}
		spec.Extensions = exts
		uc = utls.UClient(raw, cfg, utls.HelloCustom)
		if err := uc.ApplyPreset(&spec); err != nil {
			raw.Close()
			return nil, err
		}
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	} else {
		_ = raw.SetDeadline(time.Now().Add(headerTimeout))
	}
	if err := uc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	if uc.ConnectionState().Version != utls.VersionTLS13 {
		raw.Close()
		return nil, errors.New("the server did not speak TLS 1.3")
	}
	_ = raw.SetDeadline(time.Time{})
	return uc, nil
}

// chromeConnect is chromeDial for a pooled dialer.
func chromeConnect(server, fingerprint, sni string, alpn []string) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		c, err := chromeDial(ctx, server, sni, fingerprint, alpn)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
}
