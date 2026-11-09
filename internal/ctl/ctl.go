// Package ctl is how the command line talks to the running service: a small
// HTTP API on a unix socket only root can open.
package ctl

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/amor7/pol/internal/relay"
	"github.com/amor7/pol/internal/tunnel"
)

// Path is the socket; systemd creates /run/pol for the service.
func Path() string {
	if p := os.Getenv("POL_SOCK"); p != "" {
		return p
	}
	return "/run/pol/pol.sock"
}

// Status is what the service reports about itself.
type Status struct {
	Role    string `json:"role"`
	Version string `json:"version"`
	Started int64  `json:"started"`

	// server
	Listen string              `json:"listen,omitempty"`
	Server *tunnel.ServerStats `json:"server,omitempty"`

	// relay
	Target string              `json:"target,omitempty"` // the server it tunnels to
	Modes  []tunnel.ModeStatus `json:"modes,omitempty"`
	Ports  []relay.PortStatus  `json:"ports,omitempty"`
}

// SpeedFunc measures one mode: bits per second down and up.
type SpeedFunc func(mode string, mb, streams int) (down, up float64, err error)

// SpeedResult is one mode's speed test.
type SpeedResult struct {
	Mode string  `json:"mode"`
	Down float64 `json:"down"`
	Up   float64 `json:"up"`
	Err  string  `json:"err,omitempty"`
}

// Serve answers on the socket until ctx ends. speed may be nil (the server
// has nothing to measure).
func Serve(ctx context.Context, status func() Status, reload func() error, speed SpeedFunc) error {
	p := Path()
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.Remove(p)
	l, err := net.Listen("unix", p)
	if err != nil {
		return err
	}
	_ = os.Chmod(p, 0o600)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status())
	})
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		if err := reload(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /speed", func(w http.ResponseWriter, r *http.Request) {
		if speed == nil {
			http.Error(w, "the speed test runs on the relay", http.StatusBadRequest)
			return
		}
		mode := r.URL.Query().Get("mode")
		mb, _ := strconv.Atoi(r.URL.Query().Get("mb"))
		streams, _ := strconv.Atoi(r.URL.Query().Get("streams"))
		down, up, err := speed(mode, max(1, min(mb, 200)), max(1, min(streams, 16)))
		res := SpeedResult{Mode: mode, Down: down, Up: up}
		if err != nil {
			res.Err = err.Error()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		srv.Close()
		os.Remove(p)
	}()
	err = srv.Serve(l)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func client(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", Path())
		}},
	}
}

// Get asks the running service for its status.
func Get() (*Status, error) {
	resp, err := client(5 * time.Second).Get("http://pol/status")
	if err != nil {
		return nil, fmt.Errorf("the pol service is not running (start it with `pol start`)")
	}
	defer resp.Body.Close()
	var s Status
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Reload makes the service read its configuration now. It returns false
// when the service is not running (it will read the file when it starts).
func Reload() (bool, error) {
	resp, err := client(5*time.Second).Post("http://pol/reload", "", nil)
	if err != nil {
		return false, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		var b [300]byte
		n, _ := resp.Body.Read(b[:])
		return true, fmt.Errorf("the service did not take the change: %s", b[:n])
	}
	return true, nil
}

// Speed has the running service measure one mode.
func Speed(mode string, mb, streams int) (*SpeedResult, error) {
	q := url.Values{"mode": {mode}, "mb": {strconv.Itoa(mb)}, "streams": {strconv.Itoa(streams)}}
	resp, err := client(5*time.Minute).Post("http://pol/speed?"+q.Encode(), "", nil)
	if err != nil {
		return nil, fmt.Errorf("the pol service is not running (start it with `pol start`)")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var b [300]byte
		n, _ := resp.Body.Read(b[:])
		return nil, fmt.Errorf("%s", b[:n])
	}
	var r SpeedResult
	err = json.NewDecoder(resp.Body).Decode(&r)
	return &r, err
}
