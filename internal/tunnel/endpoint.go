package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// What the server answers to a stream request, in modes that answer with
// one byte.
const (
	statusOK byte = iota
	statusBadTarget
	statusForbidden
	statusUnreachable
)

func statusText(b byte) string {
	switch b {
	case statusForbidden:
		return "only this machine's ports may be reached"
	case statusUnreachable:
		return "nothing answers there"
	default:
		return "bad target"
	}
}

func httpStatus(b byte) int {
	switch b {
	case statusForbidden:
		return http.StatusForbidden
	case statusUnreachable:
		return http.StatusBadGateway
	default:
		return http.StatusBadRequest
	}
}

// statusErr turns a refusal into the error relays see.
func statusErr(b byte, target string) error {
	switch b {
	case statusForbidden:
		return fmt.Errorf("%w: only the server's own ports may be reached (any_target allows more)", ErrRejected)
	case statusUnreachable:
		return fmt.Errorf("%w: nothing answers on %s", ErrRejected, target)
	default:
		return fmt.Errorf("%w: bad target %q", ErrRejected, target)
	}
}

// ErrRejected marks an answer from a healthy server that refused one
// stream (wrong port, nothing listening): the connection itself is fine.
var ErrRejected = errors.New("rejected by the server")

// Targets with a special meaning.
const (
	speedDown = "@down:" // @down:<MB> sends MB megabytes, for `pol speedtest`
	speedUp   = "@up"    // swallows everything, then says how much
	udpPrefix = "udp:"   // udp:host:port carries framed datagrams
	// targetPing is answered and closed at once: a health check that proves
	// the whole road works.
	targetPing = "@ping"
)

// udpIdle ends a UDP stream nothing has crossed for this long.
const udpIdle = 3 * time.Minute

// endpoint is what a stream is connected to on the server.
type endpoint interface {
	// run carries the stream: what the relay sends is read from from,
	// answers are written to to.
	run(s *Server, to net.Conn, from io.Reader)
	close()
}

// endpoint checks a target and connects to it.
func (s *Server) endpoint(ctx context.Context, target string) (endpoint, byte) {
	if target == targetPing {
		return pingEP{}, statusOK
	}
	if s.Next != nil {
		// A middle hop passes everything on; the server behind it checks.
		c, err := s.Next.Dial(target)
		if err != nil {
			if errors.Is(err, ErrRejected) {
				return nil, statusUnreachable
			}
			s.Log.Warn("cannot reach the next hop", "err", err)
			return nil, statusUnreachable
		}
		return &tcpEP{c: c}, statusOK
	}
	if mb, ok := strings.CutPrefix(target, speedDown); ok {
		n, _ := strconv.Atoi(mb)
		return downEP{mb: max(1, min(n, 200))}, statusOK
	}
	if target == speedUp {
		return upEP{}, statusOK
	}
	network := "tcp"
	if t, ok := strings.CutPrefix(target, udpPrefix); ok {
		network, target = "udp", t
	}
	host, port, err := net.SplitHostPort(target)
	if n, perr := strconv.Atoi(port); err != nil || perr != nil || n < 1 || n > 65535 {
		return nil, statusBadTarget
	}
	if !s.AnyTarget && !loopback(host) {
		if time.Now().Unix()-s.refusedNoted.Swap(time.Now().Unix()) > 60 {
			s.Log.Warn("refused a target on another machine; set any_target in the config to allow it", "target", target)
		}
		return nil, statusForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := s.dialer.DialContext(ctx, network, target)
	if err != nil {
		return nil, statusUnreachable
	}
	if network == "udp" {
		return &udpEP{c: c}, statusOK
	}
	return &tcpEP{c: c}, statusOK
}

type tcpEP struct{ c net.Conn }

func (e *tcpEP) run(s *Server, to net.Conn, from io.Reader) {
	pipe(to, from, e.c, &s.up, &s.down)
}
func (e *tcpEP) close() { e.c.Close() }

// pipe copies both ways until the service side is done: relay→service
// from r (which may hold bytes already read from relay), service→relay
// into relay. up and down count the bytes.
func pipe(relay net.Conn, r io.Reader, svc net.Conn, up, down *atomic.Int64) {
	toSvc := make(chan struct{})
	go func() {
		_, _ = io.Copy(countWriter{svc, up}, r)
		_ = closeWrite(svc)
		close(toSvc)
	}()
	_, _ = io.Copy(countWriter{relay, down}, svc)
	_ = closeWrite(relay)
	// The service has finished; give the relay a moment to finish too,
	// then end the connection either way.
	select {
	case <-toSvc:
	case <-time.After(5 * time.Second):
	}
}

// udpEP carries datagrams as [2-byte length][payload] frames on the stream.
type udpEP struct{ c net.Conn }

func (e *udpEP) close() { e.c.Close() }

func (e *udpEP) run(s *Server, to net.Conn, from io.Reader) {
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := ReadDatagram(from, buf)
			if err != nil {
				e.c.Close()
				return
			}
			s.up.Add(int64(n))
			_, _ = e.c.Write(buf[:n])
		}
	}()
	buf := make([]byte, 65536)
	for {
		_ = e.c.SetReadDeadline(time.Now().Add(udpIdle))
		n, err := e.c.Read(buf)
		if err != nil {
			break
		}
		if WriteDatagram(to, buf[:n]) != nil {
			break
		}
		s.down.Add(int64(n))
	}
	_ = closeWrite(to)
}

// WriteDatagram frames one datagram onto a stream.
func WriteDatagram(w io.Writer, p []byte) error {
	if len(p) > 65535 {
		return errors.New("datagram too large")
	}
	b := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(b, uint16(len(p)))
	copy(b[2:], p)
	_, err := w.Write(b)
	return err
}

// ReadDatagram reads one framed datagram into buf.
func ReadDatagram(r io.Reader, buf []byte) (int, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n > len(buf) {
		return 0, errors.New("datagram too large")
	}
	return io.ReadFull(r, buf[:n])
}

type pingEP struct{}

func (pingEP) run(_ *Server, to net.Conn, _ io.Reader) { _ = closeWrite(to) }
func (pingEP) close()                                  {}

type downEP struct{ mb int }

func (e downEP) run(s *Server, to net.Conn, _ io.Reader) {
	_, _ = io.CopyN(to, zeroReader{}, int64(e.mb)<<20)
	_ = closeWrite(to)
}
func (downEP) close() {}

type upEP struct{}

func (upEP) run(s *Server, to net.Conn, from io.Reader) {
	n, _ := io.Copy(io.Discard, from)
	_ = binary.Write(to, binary.BigEndian, n)
	_ = closeWrite(to)
}
func (upEP) close() {}

func closeWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

type countWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c countWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.n.Add(int64(n))
	return n, err
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// ---------------------------------------------------------------- speed

// Dialer is any mode's way of opening a stream to a target.
type Dialer interface {
	Dial(target string) (net.Conn, error)
}

// SpeedDown fetches mb megabytes through d and returns the bytes received.
func SpeedDown(ctx context.Context, d Dialer, mb int) (int64, error) {
	c, err := d.Dial(speedDown + strconv.Itoa(mb))
	if err != nil {
		return 0, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	return io.Copy(io.Discard, c)
}

// SpeedUp sends mb megabytes through d and returns what the server got.
func SpeedUp(ctx context.Context, d Dialer, mb int) (int64, error) {
	c, err := d.Dial(speedUp)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if _, err := io.CopyN(c, zeroReader{}, int64(mb)<<20); err != nil {
		return 0, err
	}
	if err := closeWrite(c); err != nil {
		return 0, err
	}
	var got int64
	err = binary.Read(c, binary.BigEndian, &got)
	return got, err
}
