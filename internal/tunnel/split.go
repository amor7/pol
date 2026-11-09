package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// The split mode: one user connection is spread over several TLS
// connections at once. Each chunk of data is numbered and sent on
// whichever connection is free; the other side puts the chunks back in
// order. On a path that throttles every TCP connection separately, a single
// download then moves at several connections' speed - which no other mode
// gives one connection.
//
// The relay opens k connections (tls mode's), sending on each
//
//	SPLIT <secret> <session> <index> <k> <target>\n
//
// The server waits until all k have arrived, connects to the target, and
// answers each with the status byte. Then chunks flow as
//
//	sequence (8) | length (4, top bit set on the last, empty one) | data

const (
	splitChunk  = 16 << 10
	splitBuffer = 32 << 20 // most out-of-order data held before reading pauses
	splitWait   = 10 * time.Second
	finBit      = 1 << 31
)

// ---------------------------------------------------------------- the session

type frame struct {
	seq  uint64
	data []byte
	fin  bool
}

// splitConn is one connection carried over several.
type splitConn struct {
	subs []net.Conn
	rds  []io.Reader

	send    chan frame
	done    chan struct{}
	once    sync.Once
	seqOut  uint64 // next sequence to send; guarded by wmu
	wmu     sync.Mutex
	finSent bool
	pending sync.WaitGroup // frames queued but not yet written

	mu      sync.Mutex
	cond    *sync.Cond
	buf     map[uint64][]byte
	held    int
	next    uint64
	finSeq  int64 // -1 until the peer's last frame is known
	cur     []byte
	err     error
	readers int // subflow readers still running
}

func newSplit(subs []net.Conn, rds []io.Reader) *splitConn {
	c := &splitConn{subs: subs, rds: rds, send: make(chan frame, 4*len(subs)), done: make(chan struct{}), buf: map[uint64][]byte{}, finSeq: -1, readers: len(subs)}
	c.cond = sync.NewCond(&c.mu)
	for i := range subs {
		go c.writer(subs[i])
		go c.reader(rds[i])
	}
	return c
}

func (c *splitConn) writer(sub net.Conn) {
	hdr := make([]byte, 12)
	for {
		select {
		case <-c.done:
			return
		case f := <-c.send:
			binary.BigEndian.PutUint64(hdr, f.seq)
			n := uint32(len(f.data))
			if f.fin {
				n |= finBit
			}
			binary.BigEndian.PutUint32(hdr[8:], n)
			_, err := sub.Write(append(hdr, f.data...))
			c.pending.Done()
			if err != nil {
				c.fail(err)
				return
			}
		}
	}
}

func (c *splitConn) reader(r io.Reader) {
	defer c.readerDone()
	hdr := make([]byte, 12)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			// A subflow the peer closed cleanly only ends this reader: the
			// others may still be bringing in the last chunks.
			if !errors.Is(err, io.EOF) {
				c.fail(err)
			}
			return
		}
		seq := binary.BigEndian.Uint64(hdr)
		n := binary.BigEndian.Uint32(hdr[8:])
		fin := n&finBit != 0
		n &^= finBit
		if n > 1<<20 {
			c.fail(errors.New("split: oversized chunk"))
			return
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(r, data); err != nil {
			c.fail(err)
			return
		}
		c.mu.Lock()
		// Hold back when too much has arrived out of order - unless this is
		// the very chunk everything is waiting for.
		for c.held > splitBuffer && seq != c.next && c.err == nil {
			c.cond.Wait()
		}
		if c.err != nil {
			c.mu.Unlock()
			return
		}
		if fin {
			c.finSeq = int64(seq)
		} else {
			c.buf[seq] = data
			c.held += len(data)
		}
		c.cond.Broadcast()
		c.mu.Unlock()
		if fin {
			return
		}
	}
}

// readerDone notes a subflow reader has stopped; when all have and the
// peer's last chunk never came, the connection was cut.
func (c *splitConn) readerDone() {
	c.mu.Lock()
	c.readers--
	if c.readers == 0 && c.finSeq < 0 && c.err == nil {
		c.err = io.ErrUnexpectedEOF
	}
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *splitConn) fail(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.cond.Broadcast()
	c.mu.Unlock()
	c.once.Do(func() {
		close(c.done)
		for _, s := range c.subs {
			s.Close()
		}
	})
}

func (c *splitConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if len(c.cur) > 0 {
			n := copy(p, c.cur)
			c.cur = c.cur[n:]
			return n, nil
		}
		if d, ok := c.buf[c.next]; ok {
			delete(c.buf, c.next)
			c.held -= len(d)
			c.next++
			c.cur = d
			c.cond.Broadcast()
			continue
		}
		if c.finSeq >= 0 && c.next == uint64(c.finSeq) {
			return 0, io.EOF
		}
		if c.err != nil {
			return 0, c.err
		}
		c.cond.Wait()
	}
}

func (c *splitConn) queue(f frame) error {
	c.pending.Add(1)
	select {
	case c.send <- f:
		return nil
	case <-c.done:
		c.pending.Done()
		return net.ErrClosed
	}
}

func (c *splitConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.finSent {
		return 0, errors.New("split: write after close")
	}
	written := 0
	for len(p) > 0 {
		n := min(len(p), splitChunk)
		d := make([]byte, n)
		copy(d, p[:n])
		if err := c.queue(frame{seq: c.seqOut, data: d}); err != nil {
			return written, err
		}
		c.seqOut++
		written += n
		p = p[n:]
	}
	return written, nil
}

// CloseWrite sends the last, empty chunk and waits until everything queued
// has gone out, so closing afterwards loses nothing.
func (c *splitConn) CloseWrite() error {
	c.wmu.Lock()
	if c.finSent {
		c.wmu.Unlock()
		return nil
	}
	c.finSent = true
	err := c.queue(frame{seq: c.seqOut, fin: true})
	c.wmu.Unlock()
	if err != nil {
		return err
	}
	flushed := make(chan struct{})
	go func() { c.pending.Wait(); close(flushed) }()
	select {
	case <-flushed:
		return nil
	case <-c.done:
		return net.ErrClosed
	}
}

func (c *splitConn) Close() error {
	c.fail(net.ErrClosed)
	return nil
}

func (c *splitConn) LocalAddr() net.Addr              { return c.subs[0].LocalAddr() }
func (c *splitConn) RemoteAddr() net.Addr             { return c.subs[0].RemoteAddr() }
func (c *splitConn) SetDeadline(time.Time) error      { return nil }
func (c *splitConn) SetReadDeadline(time.Time) error  { return nil }
func (c *splitConn) SetWriteDeadline(time.Time) error { return nil }

// ---------------------------------------------------------------- server side

type splitPending struct {
	subs   []net.Conn
	got    int
	target string
	ip     string
	timer  *time.Timer
}

func (s *Server) joinSplit(c net.Conn, ip, id string, idx, k int, target string) {
	if k < 2 || k > 16 || idx < 0 || idx >= k || len(id) > 64 {
		c.Close()
		return
	}
	s.mu.Lock()
	if s.splits == nil {
		s.splits = map[string]*splitPending{}
	}
	p := s.splits[id]
	if p == nil {
		p = &splitPending{subs: make([]net.Conn, k), target: target, ip: ip}
		s.splits[id] = p
		p.timer = time.AfterFunc(splitWait, func() {
			s.mu.Lock()
			if s.splits[id] == p {
				delete(s.splits, id)
				for _, sc := range p.subs {
					if sc != nil {
						sc.Close()
					}
				}
			}
			s.mu.Unlock()
		})
	}
	if len(p.subs) != k || p.subs[idx] != nil || p.target != target {
		s.mu.Unlock()
		c.Close()
		return
	}
	p.subs[idx] = c
	p.got++
	if p.got < k {
		s.mu.Unlock()
		return
	}
	delete(s.splits, id)
	p.timer.Stop()
	s.mu.Unlock()

	ep, st := s.endpoint(context.Background(), target)
	for _, sc := range p.subs {
		_, _ = sc.Write([]byte{st})
	}
	if ep == nil {
		for _, sc := range p.subs {
			sc.Close()
		}
		return
	}
	defer ep.close()
	rds := make([]io.Reader, k)
	for i, sc := range p.subs {
		rds[i] = sc
	}
	sc := newSplit(p.subs, rds)
	defer sc.Close()
	if !s.track(sc, true) {
		return
	}
	defer s.track(sc, false)
	s.begin(p.ip)
	defer s.end(p.ip)
	ep.run(s, sc, sc)
}

// ---------------------------------------------------------------- relay side

// SplitClient is the split mode's relay side, built on tls mode's
// connections.
type SplitClient struct {
	base   *LineDialer
	secret string
	k      int
	open   atomic.Int64
}

func NewSplitClient(base *LineDialer, secret string, k int) *SplitClient {
	return &SplitClient{base: base, secret: secret, k: max(2, min(k, 16))}
}

func (d *SplitClient) Dial(target string) (net.Conn, error) {
	var last error
	for attempt := range 2 {
		c, err := d.try(target, attempt > 0)
		if err == nil {
			d.open.Add(1)
			return &countedConn{Conn: c, done: func() { d.open.Add(-1) }}, nil
		}
		if errors.Is(err, ErrRejected) {
			return nil, err
		}
		last = err
	}
	return nil, last
}

// try opens the k connections; fresh skips the pool, for a second try after
// a pooled connection turned out stale.
func (d *SplitClient) try(target string, fresh bool) (net.Conn, error) {
	id := make([]byte, 12)
	_, _ = rand.Read(id)
	sid := hex.EncodeToString(id)
	subs := make([]net.Conn, 0, d.k)
	closeAll := func() {
		for _, s := range subs {
			s.Close()
		}
	}
	for i := range d.k {
		var c net.Conn
		var err error
		if fresh {
			c, err = d.base.fresh(context.Background())
		} else {
			c, _, err = d.base.get()
		}
		if err != nil {
			closeAll()
			return nil, err
		}
		subs = append(subs, c)
		_ = c.SetDeadline(time.Now().Add(headerTimeout))
		line := "SPLIT " + d.secret + " " + sid + " " + strconv.Itoa(i) + " " + strconv.Itoa(d.k) + " " + target + "\n"
		if _, err := io.WriteString(c, line); err != nil {
			closeAll()
			return nil, err
		}
	}
	rds := make([]io.Reader, d.k)
	for i, c := range subs {
		var b [1]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			closeAll()
			return nil, fmt.Errorf("split: the server closed a connection - is the server updated (`pol update`)? %w", err)
		}
		if b[0] != statusOK {
			closeAll()
			return nil, statusErr(b[0], target)
		}
		_ = c.SetDeadline(time.Time{})
		rds[i] = c
	}
	return newSplit(subs, rds), nil
}

func (d *SplitClient) Status() ModeStatus {
	st := d.base.Status()
	st.Open = d.open.Load()
	st.Note = strconv.Itoa(d.k) + " connections per user connection"
	st.Ready = 0
	return st
}
