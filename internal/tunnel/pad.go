package tunnel

import (
	"encoding/binary"
	"io"
	"math/rand/v2"
	"net"
	"sync"
)

// The shield modes add padding to what a stream carries, so its packet
// sizes stop showing what is inside. The telling part is a connection's
// first packets: a user's own TLS handshake carried inside the tunnel's
// TLS has a recognisable rhythm of sizes (TLS inside TLS). The first
// frames each way are padded out to random sizes; later ones get a little
// padding, and long writes are cut at random lengths.
//
// A frame is 2 bytes of data length, 2 of padding length, the data, then
// the padding. It all travels inside the tunnel's own encryption.

const (
	padEarly    = 8     // frames padded heavily at the start
	padMaxFrame = 16384 // data in one frame, at most
)

type padConn struct {
	net.Conn
	wmu  sync.Mutex
	sent int
	// reading
	left int // data bytes still to come in this frame
	skip int // padding after them
}

func newPadConn(c net.Conn) *padConn { return &padConn{Conn: c} }

func (c *padConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for c.left == 0 {
		if c.skip > 0 {
			if _, err := io.CopyN(io.Discard, c.Conn, int64(c.skip)); err != nil {
				return 0, unexpected(err)
			}
			c.skip = 0
		}
		var h [4]byte
		if _, err := io.ReadFull(c.Conn, h[:]); err != nil {
			return 0, err // io.EOF at a frame boundary is a clean end
		}
		c.left, c.skip = int(binary.BigEndian.Uint16(h[:2])), int(binary.BigEndian.Uint16(h[2:]))
	}
	n, err := c.Conn.Read(p[:min(len(p), c.left)])
	c.left -= n
	if err == io.EOF && c.left > 0 {
		err = io.ErrUnexpectedEOF
	}
	if err == io.EOF && n > 0 {
		err = nil
	}
	return n, err
}

func unexpected(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

func (c *padConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		n := min(len(p), 4096+rand.IntN(padMaxFrame-4096+1))
		var pad int
		switch {
		case c.sent < padEarly:
			if target := 300 + rand.IntN(1100); n < target {
				pad = target - n
			} else {
				pad = rand.IntN(64)
			}
		case n < 1024:
			pad = rand.IntN(256)
		default:
			pad = rand.IntN(64)
		}
		c.sent++
		buf := make([]byte, 4+n+pad)
		binary.BigEndian.PutUint16(buf[:2], uint16(n))
		binary.BigEndian.PutUint16(buf[2:4], uint16(pad))
		copy(buf[4:], p[:n])
		if _, err := c.Conn.Write(buf); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *padConn) CloseWrite() error { return closeWrite(c.Conn) }

// Shield is a line mode (tls, xhttp) with padded streams.
type Shield struct {
	L *LineDialer
}

func (s Shield) Dial(target string) (net.Conn, error) {
	c, err := s.L.dial("POL1P", target)
	if err != nil {
		return nil, err
	}
	return newPadConn(c), nil
}
