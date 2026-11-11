package tunnel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// The auto mode is not a road of its own: it keeps the other modes ranked
// and sends each new connection down the best one that works. Every few
// minutes it checks that each mode still answers (a stream that opens and
// closes, a few hundred bytes); every few hours it measures their speed
// (a megabyte down each). A connection that cannot get through on the mode
// at the top is tried on the next at once, and that mode is set aside for a
// while - so a mode that is blocked costs one failed attempt, not an outage.

const (
	autoHealthEvery = 5 * time.Minute
	autoSpeedEvery  = 3 * time.Hour
	autoBench       = 30 * time.Minute // a mode that failed is not used for this long
	autoTries       = 3
)

// Auto picks among modes. Get returns a mode's dialer (or nil if that mode
// is not set up on this relay).
type Auto struct {
	Spec  string   // as written in the config: "auto" or "auto:split,tls"
	Modes []string // candidates, in the order to prefer when nothing is known
	Get   func(mode string) Dialer
	Log   *slog.Logger

	mu      sync.Mutex
	speed   map[string]float64   // bits per second, last measured
	benched map[string]time.Time // until when a mode is set aside
	using   string
	checked time.Time
	kick    chan struct{}
}

// ranked is the candidates, best first, without the benched ones (unless
// all are benched: then everything, so something is always tried).
func (a *Auto) ranked() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	var ok, benched []string
	for _, m := range a.Modes {
		if a.Get(m) == nil {
			continue
		}
		if until, b := a.benched[m]; b && now.Before(until) {
			benched = append(benched, m)
		} else {
			ok = append(ok, m)
		}
	}
	order := map[string]int{}
	for i, m := range a.Modes {
		order[m] = i
	}
	sort.SliceStable(ok, func(i, j int) bool {
		si, sj := a.speed[ok[i]], a.speed[ok[j]]
		if si != sj {
			return si > sj
		}
		return order[ok[i]] < order[ok[j]]
	})
	if len(ok) == 0 {
		return benched
	}
	return ok
}

func (a *Auto) bench(m string, err error) {
	a.mu.Lock()
	if a.benched == nil {
		a.benched = map[string]time.Time{}
	}
	a.benched[m] = time.Now().Add(autoBench)
	a.mu.Unlock()
	a.Log.Warn("auto: setting a mode aside", "mode", m, "err", err)
	a.nudge()
}

func (a *Auto) nudge() {
	a.mu.Lock()
	k := a.kick
	a.mu.Unlock()
	if k != nil {
		select {
		case k <- struct{}{}:
		default:
		}
	}
}

// Dial opens a stream on the best mode that works.
func (a *Auto) Dial(target string) (net.Conn, error) {
	var last error = errors.New("auto: no mode is set up")
	for i, m := range a.ranked() {
		if i >= autoTries {
			break
		}
		c, err := a.Get(m).Dial(target)
		if err == nil {
			a.mu.Lock()
			if a.using != m {
				if a.using != "" {
					a.Log.Info("auto: now using another mode", "mode", m, "was", a.using)
				}
				a.using = m
			}
			a.mu.Unlock()
			return c, nil
		}
		if errors.Is(err, ErrRejected) {
			return nil, err // the mode works; the target does not
		}
		last = err
		a.bench(m, err)
	}
	return nil, last
}

// Watch keeps the ranking current until ctx ends.
func (a *Auto) Watch(ctx context.Context) {
	a.mu.Lock()
	a.kick = make(chan struct{}, 1)
	kick := a.kick
	a.mu.Unlock()
	lastSpeed := time.Time{}
	for {
		if time.Since(lastSpeed) >= autoSpeedEvery {
			a.measure(ctx)
			lastSpeed = time.Now()
		} else {
			a.health(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-kick:
			// Something failed: check again soon, not at once - the
			// network may be having a bad moment.
			select {
			case <-ctx.Done():
				return
			case <-time.After(20 * time.Second):
			}
		case <-time.After(autoHealthEvery):
		}
	}
}

// health checks that every candidate still answers.
func (a *Auto) health(ctx context.Context) {
	for _, m := range a.Modes {
		d := a.Get(m)
		if d == nil || ctx.Err() != nil {
			continue
		}
		if err := ping(d); err != nil {
			a.mu.Lock()
			if a.benched == nil {
				a.benched = map[string]time.Time{}
			}
			a.benched[m] = time.Now().Add(autoHealthEvery)
			a.mu.Unlock()
		} else {
			a.mu.Lock()
			delete(a.benched, m)
			a.mu.Unlock()
		}
	}
	a.mu.Lock()
	a.checked = time.Now()
	a.mu.Unlock()
}

func ping(d Dialer) error {
	c, err := d.Dial(targetPing)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(headerTimeout))
	_, err = io.Copy(io.Discard, c)
	return err
}

// measure takes every candidate's speed, one after another.
func (a *Auto) measure(ctx context.Context) {
	for _, m := range a.Modes {
		d := a.Get(m)
		if d == nil || ctx.Err() != nil {
			continue
		}
		mctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		start := time.Now()
		n, err := SpeedDown(mctx, d, 1)
		cancel()
		a.mu.Lock()
		if a.speed == nil {
			a.speed = map[string]float64{}
		}
		if a.benched == nil {
			a.benched = map[string]time.Time{}
		}
		if err != nil || n == 0 {
			a.speed[m] = 0
			a.benched[m] = time.Now().Add(autoHealthEvery)
		} else {
			a.speed[m] = float64(n*8) / time.Since(start).Seconds()
			delete(a.benched, m)
		}
		a.mu.Unlock()
	}
	a.mu.Lock()
	a.checked = time.Now()
	a.mu.Unlock()
	if r := a.ranked(); len(r) > 0 {
		a.Log.Info("auto: modes ranked", "best", r[0], "order", strings.Join(r, ","))
	}
}

// Status says which mode auto is on and how it ranks them.
func (a *Auto) Status() ModeStatus {
	r := a.ranked()
	a.mu.Lock()
	defer a.mu.Unlock()
	st := ModeStatus{Up: len(r) > 0}
	if len(r) > 0 {
		st.Note = "best now: " + r[0]
		if len(r) > 1 {
			st.Note += ", then " + strings.Join(r[1:min(len(r), 4)], ", ")
		}
	}
	if a.using != "" {
		st.Note += " · last used " + a.using
	}
	if !st.Up {
		st.Err = "no mode answers"
	}
	return st
}
