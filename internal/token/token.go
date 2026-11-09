// Package token carries everything a relay needs to reach its server in one
// string the server prints and the relay is given.
package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

const prefix = "pol1_"

type Token struct {
	Server      string `json:"s"` // host:port of the tunnel
	Fingerprint string `json:"f"` // the server certificate's SHA-256
	Secret      string `json:"k"`
	SNI         string `json:"n"`
}

func (t Token) String() string {
	b, _ := json.Marshal(t)
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// Parse reads a token, forgiving the spaces and line breaks that copying out
// of a terminal tends to add.
func Parse(s string) (Token, error) {
	s = strings.Join(strings.Fields(s), "")
	var t Token
	if !strings.HasPrefix(s, prefix) {
		return t, errors.New("that is not a pol token (it should start with " + prefix + ")")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, prefix))
	if err != nil {
		return t, errors.New("the token is damaged - copy it again in one piece")
	}
	if err := json.Unmarshal(b, &t); err != nil || t.Server == "" || t.Fingerprint == "" || t.Secret == "" {
		return t, errors.New("the token is damaged - copy it again in one piece")
	}
	return t, nil
}

const linkPrefix = "pol1r_"

// LinkToken is what `pol reverse` prints on the relay for `pol link` on the
// server: where the relay listens, its certificate, and the server's own
// secret so the server knows the relay is one of its own.
type LinkToken struct {
	Addr        string `json:"a"`
	Fingerprint string `json:"f"`
	Secret      string `json:"k"`
	SNI         string `json:"n,omitempty"`
}

func (t LinkToken) String() string {
	b, _ := json.Marshal(t)
	return linkPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// ParseLink reads a link token.
func ParseLink(s string) (LinkToken, error) {
	s = strings.Join(strings.Fields(s), "")
	var t LinkToken
	if !strings.HasPrefix(s, linkPrefix) {
		return t, errors.New("that is not a reverse-mode token (it should start with " + linkPrefix + " - get it with `pol reverse` on the relay)")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, linkPrefix))
	if err != nil || json.Unmarshal(b, &t) != nil || t.Addr == "" || t.Fingerprint == "" || t.Secret == "" {
		return t, errors.New("the token is damaged - copy it again in one piece")
	}
	return t, nil
}
