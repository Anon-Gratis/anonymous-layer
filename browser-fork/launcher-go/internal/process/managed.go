// Package process provides a lightweight process supervisor for the
// launcher: each managed child (tor, bridge, browser) wraps an
// exec.Cmd and the Supervisor tears them down in reverse-start order
// on shutdown.
//
// Platform-specific bits (process groups, signal semantics) live in
// process_unix.go / process_windows.go behind build tags. This file
// stays portable.
package process

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"sync"
	"time"
)

// Managed wraps a child process the launcher is responsible for. If
// Cmd is nil the process is "attached" (e.g., a bridge already
// running on the port) — Start is a no-op, Stop is a no-op, only the
// readiness probe runs.
type Managed struct {
	Name        string
	Cmd         *exec.Cmd
	GracePeriod time.Duration                       // SIGTERM grace before SIGKILL
	ReadyCheck  func(ctx context.Context) error    // poll until ready or ctx cancelled
	startOrder  int                                  // assigned by Supervisor
}

// Start launches the wrapped process. No-op if attached (Cmd == nil).
// Returns the error from exec.Cmd.Start, if any.
func (m *Managed) Start() error {
	if m.Cmd == nil {
		return nil
	}
	// Put each child in its own process group (platform-specific) so
	// we can kill the whole group without taking out the launcher.
	setupProcessGroup(m.Cmd)
	if err := m.Cmd.Start(); err != nil {
		return fmt.Errorf("%s start: %w", m.Name, err)
	}
	return nil
}

// WaitReady blocks until the readiness check passes or ctx is cancelled.
// If the underlying process dies before ready, returns an error.
func (m *Managed) WaitReady(ctx context.Context) error {
	if m.ReadyCheck == nil {
		return nil
	}
	// Poll the readiness check in parallel with a death watcher so
	// we don't keep probing after the process exited.
	deathCh := make(chan struct{})
	if m.Cmd != nil && m.Cmd.Process != nil {
		go func() {
			_, _ = m.Cmd.Process.Wait()
			close(deathCh)
		}()
	}
	readyCh := make(chan error, 1)
	go func() { readyCh <- m.ReadyCheck(ctx) }()
	select {
	case err := <-readyCh:
		return err
	case <-deathCh:
		return fmt.Errorf("%s died during startup", m.Name)
	case <-ctx.Done():
		return fmt.Errorf("%s did not become ready in time: %w", m.Name, ctx.Err())
	}
}

// Stop sends a graceful terminate, waits GracePeriod, then a hard kill.
// No-op if attached (Cmd == nil) or never started.
func (m *Managed) Stop() {
	if m.Cmd == nil || m.Cmd.Process == nil {
		return
	}
	terminateGroup(m.Cmd.Process)
	if m.GracePeriod <= 0 {
		m.GracePeriod = 2 * time.Second
	}
	timer := time.NewTimer(m.GracePeriod)
	defer timer.Stop()
	done := make(chan struct{})
	go func() {
		_, _ = m.Cmd.Process.Wait()
		close(done)
	}()
	select {
	case <-done:
		return
	case <-timer.C:
		killGroup(m.Cmd.Process)
		<-done
	}
}

// Supervisor owns a set of Managed processes and tears them down in
// reverse-start order on Shutdown. All methods are safe for concurrent
// use.
type Supervisor struct {
	mu       sync.Mutex
	children []*Managed
	seq      int
}

// Add registers a Managed process with the supervisor. Order of Add
// calls determines reverse-stop order. Returns the same pointer for
// chaining.
func (s *Supervisor) Add(m *Managed) *Managed {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	m.startOrder = s.seq
	s.children = append(s.children, m)
	return m
}

// Shutdown stops every registered child in reverse-start order. Each
// Stop is bounded by its own GracePeriod; this method also enforces an
// overall budget via ctx.
func (s *Supervisor) Shutdown(ctx context.Context) {
	s.mu.Lock()
	kids := make([]*Managed, len(s.children))
	copy(kids, s.children)
	s.mu.Unlock()
	sort.SliceStable(kids, func(i, j int) bool {
		return kids[i].startOrder > kids[j].startOrder
	})
	done := make(chan struct{})
	go func() {
		for _, k := range kids {
			k.Stop()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		// Overall budget blown — fire hard-kill at everything left
		// and move on. Better to leave orphans than to hang forever.
		for _, k := range kids {
			if k.Cmd != nil && k.Cmd.Process != nil {
				killGroup(k.Cmd.Process)
			}
		}
	}
}

// ErrNotRunning is returned by readiness checks when the process exited
// before becoming ready. Callers can distinguish this from a timeout.
var ErrNotRunning = errors.New("process is not running")
