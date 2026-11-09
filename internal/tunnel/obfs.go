package tunnel

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"time"
)

// The obfs mode: plain TCP to the tunnel port carrying an AES-256-CTR
// stream, with no TLS handshake for anyone to recognise - from the first
// byte it looks like noise. The relay opens with
//
//	nonce (32 random bytes) | E( time (8) | pad length (1) | padding )
//
// keys for each direction are derived from the secret and the nonce, and a
// nonce is accepted once within a two-minute window so recordings cannot be
// replayed. Then the line protocol runs inside, encrypted.
//
// The nonce's first byte is never 0x16 (a TLS handshake) or an ASCII
// capital (an HTTP request); that is how the shared port tells them apart.

const (
	obfsNonceLen = 32
	obfsSkew     = 120 // seconds either way
)

func obfsStream(secret string, nonce []byte, label string) cipher.Stream {
	mac := func(tag string) []byte {
		h := hmac.New(sha256.New, []byte(secret))
		h.Write(nonce)
		h.Write([]byte(label + tag))
		return h.Sum(nil)
	}
	block, _ := aes.NewCipher(mac("key"))
	return cipher.NewCTR(block, mac("iv")[:aes.BlockSize])
}

type obfsConn struct {
	net.Conn
	r   io.Reader
	wmu sync.Mutex
	w   cipher.Stream
	buf []byte
}

func (c *obfsConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *obfsConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if cap(c.buf) < len(p) {
		c.buf = make([]byte, len(p))
	}
	b := c.buf[:len(p)]
	c.w.XORKeyStream(b, p)
	return c.Conn.Write(b)
}

func (c *obfsConn) CloseWrite() error { return closeWrite(c.Conn) }

func (s *Server) serveObfs(c net.Conn, ip string) {
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	nonce := make([]byte, obfsNonceLen)
	if _, err := io.ReadFull(c, nonce); err != nil {
		c.Close()
		return
	}
	r := cipher.StreamReader{S: obfsStream(s.Secret, nonce, "c2s"), R: c}
	var hdr [9]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		c.Close()
		return
	}
	t := int64(binary.BigEndian.Uint64(hdr[:8]))
	if d := time.Now().Unix() - t; d > obfsSkew || d < -obfsSkew || !s.replay.fresh(nonce) {
		// Wrong secret, a replay, or a probe: read a little, say nothing,
		// hang up - nothing a scanner can learn from.
		n, _ := rand.Int(rand.Reader, big.NewInt(2048))
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, _ = io.CopyN(io.Discard, c, n.Int64())
		c.Close()
		return
	}
	if _, err := io.CopyN(io.Discard, r, int64(hdr[8])); err != nil {
		c.Close()
		return
	}
	oc := &obfsConn{Conn: c, r: r, w: obfsStream(s.Secret, nonce, "s2c")}
	s.serveLine(oc, ip, rawPreambleWait, nil)
}

// replayCache remembers nonces for as long as their timestamps are valid.
type replayCache struct {
	mu   sync.Mutex
	seen map[[obfsNonceLen]byte]int64
}

func (rc *replayCache) fresh(nonce []byte) bool {
	var k [obfsNonceLen]byte
	copy(k[:], nonce)
	now := time.Now().Unix()
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.seen == nil {
		rc.seen = map[[obfsNonceLen]byte]int64{}
	}
	if len(rc.seen) > 4096 {
		for n, t := range rc.seen {
			if now-t > 2*obfsSkew {
				delete(rc.seen, n)
			}
		}
	}
	if _, ok := rc.seen[k]; ok {
		return false
	}
	rc.seen[k] = now
	return true
}

// NewObfsClient is the obfs mode's relay side.
func NewObfsClient(server, secret string, warm int, log *slog.Logger) *LineDialer {
	return newLineDialer("obfs", secret, warm, log, func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", server)
		if err != nil {
			return nil, err
		}
		return obfsOpen(c, secret)
	})
}

func obfsOpen(c net.Conn, secret string) (net.Conn, error) {
	nonce := make([]byte, obfsNonceLen)
	for {
		_, _ = rand.Read(nonce)
		if nonce[0] != 0x16 && (nonce[0] < 'A' || nonce[0] > 'Z') {
			break
		}
	}
	pad := make([]byte, 1)
	_, _ = rand.Read(pad)
	hdr := make([]byte, 9+int(pad[0]))
	binary.BigEndian.PutUint64(hdr, uint64(time.Now().Unix()))
	hdr[8] = pad[0]
	_, _ = rand.Read(hdr[9:])
	enc := obfsStream(secret, nonce, "c2s")
	enc.XORKeyStream(hdr, hdr)
	if _, err := c.Write(append(nonce, hdr...)); err != nil {
		c.Close()
		return nil, err
	}
	return &obfsConn{Conn: c, r: cipher.StreamReader{S: obfsStream(secret, nonce, "s2c"), R: c}, w: enc}, nil
}
