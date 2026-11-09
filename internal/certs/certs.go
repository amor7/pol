// Package certs makes the server's self-signed certificate and lets relays
// trust exactly that one, by fingerprint.
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Load returns the certificate in dir, making a ten-year one the first time.
func Load(dir string) (tls.Certificate, error) {
	crt := filepath.Join(dir, "pol.crt")
	key := filepath.Join(dir, "pol.key")
	if c, err := tls.LoadX509KeyPair(crt, key); err == nil {
		return c, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &pk.PublicKey, pk)
	if err != nil {
		return tls.Certificate{}, err
	}
	kb, err := x509.MarshalECPrivateKey(pk)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(crt, key)
}

// Fingerprint is the hex SHA-256 of the certificate relays pin.
func Fingerprint(c tls.Certificate) string {
	if len(c.Certificate) == 0 {
		return ""
	}
	s := sha256.Sum256(c.Certificate[0])
	return hex.EncodeToString(s[:])
}

// Pinned trusts one certificate, by fingerprint, and nothing else.
//
// serverName goes out as SNI and nobody checks it, but it has to be there:
// filtering in Iran silently drops TLS handshakes without a server name,
// which is what a connection to a bare IP address sends by default.
func Pinned(fingerprint, serverName string) *tls.Config {
	want := strings.ToLower(fingerprint)
	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // replaced by the pin check below
		MinVersion:         tls.VersionTLS13,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("the server presented no certificate")
			}
			s := sha256.Sum256(raw[0])
			if hex.EncodeToString(s[:]) != want {
				return errors.New("the server's certificate is not the one in the token")
			}
			return nil
		},
	}
}
