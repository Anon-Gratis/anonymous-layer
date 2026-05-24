// Package bridge spawns (or attaches to) anon-browse-gui.mjs. The
// attach-mode mirrors the bash launcher's recently-added behavior:
// if the configured bridge port is already serving a healthy
// anon-bridge, skip the spawn and just attach.
package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/anon-gratis/anonymous-layer/browser-fork/launcher-go/internal/config"
	"github.com/anon-gratis/anonymous-layer/browser-fork/launcher-go/internal/process"
)

// Layout describes where the bridge node binary and JS entry point live.
type Layout struct {
	Node   string // AnonLayer/node/bin/node
	Script string // AnonLayer/bridge/bin/anon-browse-gui.mjs
	Log    string // AnonLayer/bridge.log
}

// NewLayout builds the Layout rooted at $AnonDir.
func NewLayout(anonDir string) Layout {
	return Layout{
		Node:   filepath.Join(anonDir, "node", "bin", "node"),
		Script: filepath.Join(anonDir, "bridge", "bin", "anon-browse-gui.mjs"),
		Log:    filepath.Join(anonDir, "bridge.log"),
	}
}

// Start prepares the bridge Managed process. If an existing healthy
// bridge is already on the configured port, returns a Managed in
// attach-mode (Cmd nil, no-op start/stop). Otherwise builds the
// exec.Cmd with the right CLI args for the mode (CONNECT vs.
// rendezvous).
func Start(l Layout, c *config.Config) (*process.Managed, bool, error) {
	// Attach-mode check.
	if attached, err := probeExisting(c.BridgeHost, c.BridgePort); err == nil && attached {
		return &process.Managed{
			Name:       "bridge (attached)",
			Cmd:        nil,
			ReadyCheck: nil, // already verified
		}, true, nil
	} else if !errors.Is(err, errPortFree) {
		// Port occupied by something other than our bridge — refuse.
		return nil, false, fmt.Errorf("port %d in use by non-anon service: %w", c.BridgePort, err)
	}

	// Spawn mode: build args from config.
	args := []string{l.Script,
		"--listen", c.BridgeHost,
		"--port", strconv.Itoa(c.BridgePort),
		"--no-token",
	}
	if c.IsConnectMode() {
		args = append(args, "--connect", c.Connect)
	} else {
		args = append(args,
			"--consensus", c.Consensus,
			"--da-trust", c.DATrust,
		)
		if c.Descriptor != "" {
			args = append(args, "--descriptor", c.Descriptor)
		}
		if c.DescriptorDir != "" {
			args = append(args, "--descriptor-dir", c.DescriptorDir)
		}
		if c.HSDirURL != "" {
			args = append(args, "--hsdir-url", c.HSDirURL)
		}
		if c.DAURLs != "" {
			args = append(args, "--refresh-from", c.DAURLs)
		}
		if c.AllowColocate {
			args = append(args, "--allow-co-located")
		}
	}

	// Truncate the log on fresh spawn; append in attach mode (handled
	// above by short-circuit). Matches bash behavior.
	if err := os.MkdirAll(filepath.Dir(l.Log), 0o755); err != nil {
		return nil, false, err
	}
	logFile, err := os.OpenFile(l.Log, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, false, fmt.Errorf("open bridge log: %w", err)
	}
	cmd := exec.Command(l.Node, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	return &process.Managed{
		Name:        "bridge",
		Cmd:         cmd,
		GracePeriod: 3 * time.Second,
		ReadyCheck:  healthReady(c.BridgeHost, c.BridgePort),
	}, false, nil
}

// errPortFree is a sentinel — returned by probeExisting when the port
// is free (= no squatter at all, normal spawn case).
var errPortFree = fmt.Errorf("port free")

// probeExisting reports whether the configured port is held by a
// healthy anon-bridge. Three outcomes:
//   (true,  nil)        — held by anon-bridge, attach mode
//   (false, errPortFree) — no listener, normal spawn
//   (false, otherErr)    — held by something else, refuse
func probeExisting(host string, port int) (bool, error) {
	// First: is anything listening?
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false, errPortFree
	}
	_ = c.Close()
	// Something's there — fingerprint via /api/health.
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://%s/api/health", addr))
	if err != nil {
		return false, fmt.Errorf("listener does not speak HTTP: %w", err)
	}
	defer resp.Body.Close()
	var body struct {
		OK      bool   `json:"ok"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, fmt.Errorf("listener is not anon-bridge (bad JSON)")
	}
	if !body.OK {
		return false, fmt.Errorf("listener is HTTP but not anon-bridge")
	}
	return true, nil
}

// healthReady polls /api/health until 200 (or 403 for token-gated),
// matching the bash launcher's 60×0.2s readiness wait.
func healthReady(host string, port int) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		client := &http.Client{Timeout: 1 * time.Second}
		url := fmt.Sprintf("http://%s/api/health", net.JoinHostPort(host, strconv.Itoa(port)))
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			resp, err := client.Get(url)
			if err == nil {
				code := resp.StatusCode
				_ = resp.Body.Close()
				if code == 200 || code == 403 {
					return nil
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
		return fmt.Errorf("bridge %s not ready", url)
	}
}

