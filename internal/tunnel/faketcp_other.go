//go:build !linux

package tunnel

import (
	"context"
	"errors"
	"log/slog"
	"net"
)

var errFakeTCPLinux = errors.New("faketcp runs on Linux only")

// FakeTCPSupported says whether faketcp can run here.
func FakeTCPSupported() error { return errFakeTCPLinux }

// ListenFakeTCP listens for faketcp; Linux only.
func ListenFakeTCP(int) (net.PacketConn, error) { return nil, errFakeTCPLinux }

// NewFakeTCPClient is the faketcp mode's relay side; Linux only.
func NewFakeTCPClient(_ string, _ int, secret string, log *slog.Logger) *KCPClient {
	return newKCPClient("faketcp", secret, ProfileFakeTCP, log, func(context.Context) (net.PacketConn, net.Addr, error) {
		return nil, nil, errFakeTCPLinux
	})
}
