package tunnel

import (
	"bytes"
	"context"
	"crypto"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/amor7/pol/internal/certs"
)

// The ssh mode: one real SSH connection to the tunnel port, each user
// connection a channel in it. To anyone watching it is an administrator's
// SSH session. The server's host key is its certificate's key, so the relay
// pins it as it pins the certificate; the relay logs in with the secret.
// Inside each channel the line protocol runs as in the other modes.

const sshChannel = "pol"

// enableSSH prepares the server's SSH side from its certificate.
func (s *Server) enableSSH(cert tls.Certificate) {
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return
	}
	hk, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return
	}
	cfg := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
		PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if s.Secret != "" && subtle.ConstantTimeCompare(pw, []byte(s.Secret)) == 1 {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
		MaxAuthTries: 2,
	}
	cfg.AddHostKey(hk)
	s.sshConf = cfg
}

func (s *Server) serveSSH(c net.Conn, ip string) {
	if s.sshConf == nil {
		c.Close()
		return
	}
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	sc, chans, reqs, err := ssh.NewServerConn(c, s.sshConf)
	if err != nil {
		c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != sshChannel {
			_ = nc.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(creqs)
		go s.serveLine(&sshConn{Channel: ch, la: sc.LocalAddr(), ra: sc.RemoteAddr()}, ip, 15*time.Second, nil)
	}
}

// sshConn is an SSH channel as a net.Conn.
type sshConn struct {
	ssh.Channel
	la, ra net.Addr
}

func (c *sshConn) LocalAddr() net.Addr              { return c.la }
func (c *sshConn) RemoteAddr() net.Addr             { return c.ra }
func (c *sshConn) SetDeadline(time.Time) error      { return nil }
func (c *sshConn) SetReadDeadline(time.Time) error  { return nil }
func (c *sshConn) SetWriteDeadline(time.Time) error { return nil }

// SSHClient is the ssh mode's relay side.
type SSHClient struct {
	addr, fp, secret, sni string
	log                   *slog.Logger
	mu                    sync.Mutex
	hostKey               ssh.PublicKey
	client                *ssh.Client
	healthy               atomic.Bool
	rtt                   atomic.Int64
	lastErr               atomic.Value
	open                  atomic.Int64
}

func NewSSHClient(server, fingerprint, secret, sni string, log *slog.Logger) *SSHClient {
	c := &SSHClient{addr: server, fp: fingerprint, secret: secret, sni: sni, log: log}
	c.lastErr.Store("")
	return c
}

// key learns the server's host key from its pinned certificate.
func (c *SSHClient) key(ctx context.Context) (ssh.PublicKey, error) {
	if c.hostKey != nil {
		return c.hostKey, nil
	}
	sni := c.sni
	if sni == "" {
		sni = "example.com"
	}
	d := tls.Dialer{Config: certs.Pinned(c.fp, sni)}
	conn, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("ssh: no certificate to learn the host key from")
	}
	pk, err := ssh.NewPublicKey(certs[0].PublicKey)
	if err != nil {
		return nil, err
	}
	c.hostKey = pk
	return pk, nil
}

func (c *SSHClient) conn(ctx context.Context) (*ssh.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		return c.client, nil
	}
	ctx, cancel := context.WithTimeout(ctx, headerTimeout)
	defer cancel()
	hk, err := c.key(ctx)
	if err != nil {
		c.failed(err)
		return nil, err
	}
	start := time.Now()
	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		c.failed(err)
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = nc.SetDeadline(dl)
	}
	cfg := &ssh.ClientConfig{
		User:          "root",
		Auth:          []ssh.AuthMethod{ssh.Password(c.secret)},
		ClientVersion: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
		HostKeyCallback: func(_ string, _ net.Addr, got ssh.PublicKey) error {
			if !bytes.Equal(got.Marshal(), hk.Marshal()) {
				return errors.New("the server's SSH key is not the one in the token")
			}
			return nil
		},
		Timeout: headerTimeout,
	}
	sc, chans, reqs, err := ssh.NewClientConn(nc, c.addr, cfg)
	if err != nil {
		nc.Close()
		c.failed(err)
		return nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	cl := ssh.NewClient(sc, chans, reqs)
	c.rtt.Store(int64(time.Since(start)))
	c.client = cl
	go func() {
		_ = cl.Wait()
		c.mu.Lock()
		if c.client == cl {
			c.client = nil
		}
		c.mu.Unlock()
	}()
	return cl, nil
}

func (c *SSHClient) failed(err error) {
	if c.healthy.Swap(false) {
		c.log.Warn("ssh mode down", "err", err)
	}
	c.lastErr.Store(err.Error())
}

func (c *SSHClient) Dial(target string) (net.Conn, error) {
	var last error
	for range 2 {
		cl, err := c.conn(context.Background())
		if err != nil {
			return nil, err
		}
		ch, reqs, err := cl.OpenChannel(sshChannel, nil)
		if err != nil {
			last = err
			cl.Close()
			continue
		}
		go ssh.DiscardRequests(reqs)
		sc := &sshConn{Channel: ch, la: cl.LocalAddr(), ra: cl.RemoteAddr()}
		if err := startLine(sc, "POL1 "+c.secret+" "+target, target); err != nil {
			ch.Close()
			if errors.Is(err, ErrRejected) {
				return nil, err
			}
			last = err
			continue
		}
		if !c.healthy.Swap(true) {
			c.log.Info("ssh mode up")
		}
		c.lastErr.Store("")
		c.open.Add(1)
		return &countedConn{Conn: sc, done: func() { c.open.Add(-1) }}, nil
	}
	c.failed(last)
	return nil, last
}

// Watch keeps the SSH connection up, with keepalives, until ctx ends.
func (c *SSHClient) Watch(ctx context.Context) {
	for {
		if cl, err := c.conn(ctx); err == nil {
			start := time.Now()
			if _, _, err := cl.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				c.failed(err)
				cl.Close()
			} else {
				c.rtt.Store(int64(time.Since(start)))
				if !c.healthy.Swap(true) {
					c.log.Info("ssh mode up")
				}
				c.lastErr.Store("")
			}
		}
		select {
		case <-ctx.Done():
			c.mu.Lock()
			if c.client != nil {
				c.client.Close()
				c.client = nil
			}
			c.mu.Unlock()
			return
		case <-time.After(15 * time.Second):
		}
	}
}

func (c *SSHClient) Status() ModeStatus {
	return ModeStatus{Up: c.healthy.Load(), RTTms: float64(c.rtt.Load()) / 1e6, Open: c.open.Load(), Err: c.lastErr.Load().(string)}
}

var _ = x509.Certificate{}
