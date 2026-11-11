package tunnel

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// The kcp, hop, faketcp and dns modes share one design: KCP (a reliable,
// aggressive protocol over packets) carries an smux session, every user
// connection is an smux stream, and inside each stream the line protocol
// runs as in the other modes. They differ only in what carries KCP's
// packets: plain UDP (kcp), UDP whose port keeps changing (hop), UDP dressed
// as TCP (faketcp), or DNS queries (dns). KCP's packets are encrypted with
// AES keyed from the secret; anything else arriving is dropped unanswered.

// KCPProfile is how one of these modes uses KCP.
type KCPProfile struct {
	Data, Parity int // FEC shards: Parity/Data extra traffic to rebuild lost packets
	MTU          int // largest packet this side sends; 0 for KCP's default
	Window       int // packets in flight; 0 for the default
	Interval     int // ms between KCP updates; 0 for the default
}

// Profiles of the modes.
var (
	ProfileKCP     = KCPProfile{Data: 10, Parity: 3}       // +30%: loss is rebuilt rather than resent
	ProfileHop     = KCPProfile{Data: 10, Parity: 3}       // +30%
	ProfileFakeTCP = KCPProfile{Data: 10, Parity: 2}       // +20%
	ProfileDNS     = KCPProfile{Window: 128, Interval: 40} // no FEC: every byte counts

	// ProfileDNSServer is the server's side of dns mode: its packets ride in
	// answers, which hold more than queries.
	ProfileDNSServer = KCPProfile{Window: 128, Interval: 40, MTU: dnsServerMTU}
)

func kcpCrypt(secret string) kcp.BlockCrypt {
	h := sha256.Sum256([]byte("pol kcp " + secret))
	b, _ := kcp.NewAESBlockCrypt(h[:])
	return b
}

func tuneKCP(s *kcp.UDPSession, p KCPProfile) {
	s.SetStreamMode(true)
	s.SetWriteDelay(false)
	interval := p.Interval
	if interval == 0 {
		interval = 20
	}
	s.SetNoDelay(1, interval, 2, 1)
	w := p.Window
	if w == 0 {
		w = 1024
	}
	s.SetWindowSize(w, w)
	s.SetACKNoDelay(true)
	if p.MTU > 0 {
		s.SetMtu(p.MTU)
	}
}

func smuxConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.Version = 2
	c.KeepAliveInterval = 10 * time.Second
	c.KeepAliveTimeout = 40 * time.Second
	c.MaxReceiveBuffer = 16 << 20
	c.MaxStreamBuffer = 2 << 20
	return c
}

// bigBuffers gives a UDP socket room for a burst: with the small default,
// a burst overflows it and KCP has to resend what was dropped right here.
func bigBuffers(pc net.PacketConn) {
	if u, ok := pc.(interface {
		SetReadBuffer(int) error
		SetWriteBuffer(int) error
	}); ok {
		_ = u.SetReadBuffer(4 << 20)
		_ = u.SetWriteBuffer(4 << 20)
	}
}

// ServeKCP answers a KCP-based mode on pc until the server closes.
func (s *Server) ServeKCP(pc net.PacketConn, p KCPProfile) error {
	bigBuffers(pc)
	l, err := kcp.ServeConn(kcpCrypt(s.Secret), p.Data, p.Parity, pc)
	if err != nil {
		pc.Close()
		return err
	}
	if !s.addCloser(l) {
		l.Close()
		return nil
	}
	for {
		sess, err := l.AcceptKCP()
		if err != nil {
			return nil
		}
		tuneKCP(sess, p)
		go func() {
			mux, err := smux.Server(sess, smuxConfig())
			if err != nil {
				sess.Close()
				return
			}
			defer mux.Close()
			defer sess.Close()
			ip := hostOf(sess.RemoteAddr())
			for {
				st, err := mux.AcceptStream()
				if err != nil {
					return
				}
				go s.serveLine(st, ip, 15*time.Second, nil)
			}
		}()
	}
}

// KCPClient is the relay side of a KCP-based mode: one KCP session,
// redialled when it dies, with an smux stream per user connection.
type KCPClient struct {
	name    string
	secret  string
	prof    KCPProfile
	dial    func(ctx context.Context) (net.PacketConn, net.Addr, error)
	log     *slog.Logger
	mu      sync.Mutex
	sess    *smux.Session
	closeFn func()
	healthy atomic.Bool
	rtt     atomic.Int64
	lastErr atomic.Value
	open    atomic.Int64
}

func newKCPClient(name, secret string, p KCPProfile, log *slog.Logger, dial func(context.Context) (net.PacketConn, net.Addr, error)) *KCPClient {
	k := &KCPClient{name: name, secret: secret, prof: p, dial: dial, log: log}
	k.lastErr.Store("")
	return k
}

// NewKCPClient is the kcp mode: KCP over plain UDP to addr.
func NewKCPClient(addr, secret string, log *slog.Logger) *KCPClient {
	return newKCPClient("kcp", secret, ProfileKCP, log, func(context.Context) (net.PacketConn, net.Addr, error) {
		ra, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, nil, err
		}
		pc, err := net.ListenUDP("udp", nil)
		return pc, ra, err
	})
}

func (k *KCPClient) session(ctx context.Context) (*smux.Session, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.sess != nil && !k.sess.IsClosed() {
		return k.sess, nil
	}
	if k.closeFn != nil {
		k.closeFn()
		k.closeFn = nil
	}
	pc, raddr, err := k.dial(ctx)
	if err != nil {
		k.failed(err)
		return nil, err
	}
	bigBuffers(pc)
	us, err := kcp.NewConn2(raddr, kcpCrypt(k.secret), k.prof.Data, k.prof.Parity, pc)
	if err != nil {
		pc.Close()
		k.failed(err)
		return nil, err
	}
	tuneKCP(us, k.prof)
	mux, err := smux.Client(us, smuxConfig())
	if err != nil {
		us.Close()
		pc.Close()
		k.failed(err)
		return nil, err
	}
	k.sess = mux
	k.closeFn = func() {
		mux.Close()
		us.Close()
		pc.Close()
	}
	return mux, nil
}

func (k *KCPClient) drop(s *smux.Session) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.sess == s && k.closeFn != nil {
		k.closeFn()
		k.sess, k.closeFn = nil, nil
	}
}

func (k *KCPClient) failed(err error) {
	if k.healthy.Swap(false) {
		k.log.Warn(k.name+" mode down", "err", err)
	}
	k.lastErr.Store(err.Error())
}

func (k *KCPClient) ok() {
	if !k.healthy.Swap(true) {
		k.log.Info(k.name + " mode up")
	}
	k.lastErr.Store("")
}

func (k *KCPClient) stream(target string) (net.Conn, error) {
	sess, err := k.session(context.Background())
	if err != nil {
		return nil, err
	}
	st, err := sess.OpenStream()
	if err != nil {
		k.drop(sess)
		return nil, err
	}
	if err := startLine(st, "POL1 "+k.secret+" "+target, target); err != nil {
		st.Close()
		if !errors.Is(err, ErrRejected) {
			// KCP has no handshake: a session that cannot get one line
			// answered is dead (or never reached the server).
			k.drop(sess)
		}
		return nil, err
	}
	return st, nil
}

func (k *KCPClient) Dial(target string) (net.Conn, error) {
	c, err := k.stream(target)
	if err != nil {
		if !errors.Is(err, ErrRejected) {
			k.failed(err)
		}
		return nil, err
	}
	k.ok()
	k.open.Add(1)
	return &countedConn{Conn: c, done: func() { k.open.Add(-1) }}, nil
}

// Ping times a stream that is opened and answered.
func (k *KCPClient) Ping() (time.Duration, error) {
	start := time.Now()
	c, err := k.stream(targetPing)
	if err != nil {
		k.failed(err)
		return 0, err
	}
	d := time.Since(start)
	_, _ = io.Copy(io.Discard, c)
	c.Close()
	k.rtt.Store(int64(d))
	k.ok()
	return d, nil
}

// Watch keeps the session up and its state known until ctx ends.
func (k *KCPClient) Watch(ctx context.Context) {
	for {
		_, _ = k.Ping()
		select {
		case <-ctx.Done():
			k.mu.Lock()
			if k.closeFn != nil {
				k.closeFn()
				k.sess, k.closeFn = nil, nil
			}
			k.mu.Unlock()
			return
		case <-time.After(15 * time.Second):
		}
	}
}

func (k *KCPClient) Status() ModeStatus {
	return ModeStatus{Up: k.healthy.Load(), RTTms: float64(k.rtt.Load()) / 1e6, Open: k.open.Load(), Err: k.lastErr.Load().(string)}
}
