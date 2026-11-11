package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
)

// The camo mode borrows a real website's TLS. The relay connects to the pol
// server with that site's name and a browser's handshake (Chrome's, down to
// the byte); the server passes the handshake through to the real site and
// back, so the relay ends up with a genuine handshake and the site's real
// certificate - which is all anyone in between can see. Then, instead of
// talking to the site, the relay sends records of its own: they look like
// the TLS records that would follow, but are encrypted with keys derived
// from the secret and that handshake's server random. The server tries each
// record from the relay against those keys; the first one that opens tells
// it the rest is pol's, and it drops the real site. Anyone who connects
// without the secret simply gets the real site, every time.

const (
	recordMax  = 16384 + 2048
	camoChunk  = 16000
	recAppData = 0x17
	recHandsh  = 0x16
)

// DefaultCamo is the site borrowed when none is set: large, served over
// TLS 1.3, and not blocked in Iran.
const DefaultCamo = "www.microsoft.com"

// CamoRoots, when set, replaces the system's roots for checking the
// borrowed site's certificate; tests use it.
var CamoRoots *x509.CertPool

func readRecord(r io.Reader) ([]byte, error) {
	rec := make([]byte, 5, 5+1024)
	if _, err := io.ReadFull(r, rec); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(rec[3:]))
	if n > recordMax {
		return nil, errors.New("camo: oversized record")
	}
	rec = append(rec, make([]byte, n)...)
	if _, err := io.ReadFull(r, rec[5:]); err != nil {
		return nil, err
	}
	return rec, nil
}

// serverRandom is the random of a ServerHello record, or nil.
func serverRandom(rec []byte) []byte {
	if len(rec) < 43 || rec[0] != recHandsh || rec[5] != 2 {
		return nil
	}
	return append([]byte(nil), rec[11:43]...)
}

type camoKeys struct{ c2s, s2c cipher.AEAD }

func newCamoKeys(secret string, random []byte) camoKeys {
	mk := func(label string) cipher.AEAD {
		h := hmac.New(sha256.New, []byte(secret))
		h.Write([]byte("pol camo " + label))
		h.Write(random)
		b, _ := aes.NewCipher(h.Sum(nil))
		g, _ := cipher.NewGCM(b)
		return g
	}
	return camoKeys{c2s: mk("c2s"), s2c: mk("s2c")}
}

func ctrNonce(n uint64) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint64(b[4:], n)
	return b
}

// camoConn carries data as encrypted records after the borrowed handshake.
type camoConn struct {
	net.Conn
	br      *bufio.Reader
	rk, wk  cipher.AEAD
	rctr    uint64
	pending []byte
	eof     bool
	skip    bool // drop records that do not open until one does (the site's last words)

	wmu  sync.Mutex
	wctr uint64
}

func (c *camoConn) Read(p []byte) (int, error) {
	for len(c.pending) == 0 {
		if c.eof {
			return 0, io.EOF
		}
		rec, err := readRecord(c.br)
		if err != nil {
			return 0, err
		}
		if rec[0] != recAppData {
			if c.skip {
				continue
			}
			return 0, errors.New("camo: unexpected record")
		}
		pt, err := c.rk.Open(nil, ctrNonce(c.rctr), rec[5:], rec[:3])
		if err != nil {
			if c.skip {
				continue
			}
			return 0, errors.New("camo: a record did not open")
		}
		c.skip = false
		c.rctr++
		if len(pt) == 0 {
			c.eof = true
			continue
		}
		c.pending = pt
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *camoConn) seal(p []byte) error {
	hdr := []byte{recAppData, 3, 3, 0, 0}
	out := c.wk.Seal(hdr, ctrNonce(c.wctr), p, hdr[:3])
	c.wctr++
	binary.BigEndian.PutUint16(out[3:], uint16(len(out)-5))
	_, err := c.Conn.Write(out)
	return err
}

func (c *camoConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	for len(p) > 0 {
		n := min(len(p), camoChunk)
		if err := c.seal(p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// CloseWrite sends an empty record: "nothing more from me".
func (c *camoConn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.seal(nil)
}

// helloRetry is the random a HelloRetryRequest carries instead of a real one.
var helloRetry = []byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

// helloSNI is the server name in a ClientHello record, or "".
func helloSNI(rec []byte) string {
	if len(rec) < 9 || rec[0] != recHandsh || rec[5] != 1 {
		return ""
	}
	b := rec[9:] // past the record and handshake headers
	if len(b) < 34 {
		return ""
	}
	b = b[34:] // version, random
	skip := func(n int) bool {
		if len(b) < n {
			return false
		}
		b = b[n:]
		return true
	}
	vec := func(lenBytes int) bool {
		if len(b) < lenBytes {
			return false
		}
		n := 0
		for i := range lenBytes {
			n = n<<8 | int(b[i])
		}
		return skip(lenBytes + n)
	}
	if !vec(1) || !vec(2) || !vec(1) { // session id, cipher suites, compression
		return ""
	}
	if len(b) < 2 {
		return ""
	}
	ext := b[2:]
	for len(ext) >= 4 {
		typ := int(ext[0])<<8 | int(ext[1])
		n := int(ext[2])<<8 | int(ext[3])
		if len(ext) < 4+n {
			return ""
		}
		data := ext[4 : 4+n]
		ext = ext[4+n:]
		if typ != 0 || len(data) < 5 { // server_name
			continue
		}
		l := int(data[3])<<8 | int(data[4])
		if data[2] == 0 && len(data) >= 5+l {
			return strings.ToLower(string(data[5 : 5+l]))
		}
	}
	return ""
}

// serveCamo relays a camo connection to the real site until the relay's
// first record of its own opens with the secret's keys; then it serves the
// rest as pol. Anyone else is the real site's visitor throughout.
func (s *Server) serveCamo(c net.Conn, br *bufio.Reader, ip string) {
	addr := s.CamoAddr
	if addr == "" {
		addr = net.JoinHostPort(s.Camo, "443")
	}
	site, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	var random atomic.Pointer[[]byte]
	siteDone := make(chan struct{})
	go func() {
		// The site's half: passed through as it is, noting the random.
		defer close(siteDone)
		for {
			rec, err := readRecord(site)
			if err != nil {
				return
			}
			if r := serverRandom(rec); r != nil && !bytes.Equal(r, helloRetry) && random.Load() == nil {
				random.Store(&r)
			}
			if _, err := c.Write(rec); err != nil {
				return
			}
		}
	}()
	var keys *camoKeys
	for {
		rec, err := readRecord(br)
		if err != nil {
			site.Close()
			c.Close()
			return
		}
		if rec[0] == recAppData {
			if r := random.Load(); r != nil {
				if keys == nil {
					k := newCamoKeys(s.Secret, *r)
					keys = &k
				}
				if pt, err := keys.c2s.Open(nil, ctrNonce(0), rec[5:], rec[:3]); err == nil {
					// Ours. Leave the site, and only then speak: its half
					// must not write into the connection any more.
					site.Close()
					<-siteDone
					cc := &camoConn{Conn: c, br: br, rk: keys.c2s, wk: keys.s2c, rctr: 1, pending: pt}
					s.serveLine(cc, ip, rawPreambleWait, nil)
					return
				}
			}
		}
		if _, err := site.Write(rec); err != nil {
			c.Close()
			return
		}
	}
}

// recordReader hands a TLS client its input a record at a time, never
// across the end of one, so that when the handshake is done nothing of the
// records after it is left inside the client - and it keeps the records.
type recordReader struct {
	net.Conn
	cur  []byte
	seen [][]byte
	keep bool
}

func (r *recordReader) Read(p []byte) (int, error) {
	if len(r.cur) == 0 {
		rec, err := readRecord(r.Conn)
		if err != nil {
			return 0, err
		}
		if r.keep {
			r.seen = append(r.seen, rec)
		}
		r.cur = rec
	}
	n := copy(p, r.cur)
	r.cur = r.cur[n:]
	return n, nil
}

// NewCamoClient is the camo mode's relay side: server is the pol server,
// site the website whose TLS is borrowed (DefaultCamo if empty).
func NewCamoClient(server, site, secret string, warm int, log *slog.Logger) *LineDialer {
	if site == "" {
		site = DefaultCamo
	}
	return newLineDialer("camo", secret, warm, log, func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		raw, err := d.DialContext(ctx, "tcp", server)
		if err != nil {
			return nil, err
		}
		if dl, ok := ctx.Deadline(); ok {
			_ = raw.SetDeadline(dl)
		}
		rr := &recordReader{Conn: raw, keep: true}
		uc := utls.UClient(rr, &utls.Config{ServerName: site, RootCAs: CamoRoots}, utls.HelloChrome_Auto)
		if err := uc.HandshakeContext(ctx); err != nil {
			raw.Close()
			var ce *tls.CertificateVerificationError
			var ue x509.UnknownAuthorityError
			if errors.As(err, &ce) || errors.As(err, &ue) {
				return nil, errors.New("camo: the certificate on the way is not " + site + "'s - is the server running a current pol with camo " + site + "?")
			}
			return nil, err
		}
		var random []byte
		for _, rec := range rr.seen {
			if r := serverRandom(rec); r != nil && !bytes.Equal(r, helloRetry) {
				random = r
				break
			}
		}
		if random == nil {
			raw.Close()
			return nil, errors.New("camo: no ServerHello seen")
		}
		_ = raw.SetDeadline(time.Time{})
		k := newCamoKeys(secret, random)
		// Records the site sent after its handshake (tickets) do not open
		// with our keys and are skipped until the server's first one does.
		return &camoConn{Conn: raw, br: bufio.NewReaderSize(rr.Conn, 32<<10), rk: k.s2c, wk: k.c2s, skip: true}, nil
	})
}
