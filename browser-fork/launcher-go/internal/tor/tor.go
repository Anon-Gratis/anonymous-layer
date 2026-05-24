// Package tor starts the bundled tor binary with a per-launch
// torrc (rendered from a template with random ports), tails the log
// for the launcher's readiness check, and exposes the SOCKS port for
// PAC generation.
package tor

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/anon-gratis/anonymous-layer/browser-fork/launcher-go/internal/process"
)

// Layout describes where tor's binary, templates, and runtime state live.
type Layout struct {
	Bin             string // AnonLayer/tor/bin/tor
	TorrcTemplate   string // AnonLayer/tor/etc/torrc.template
	RuntimeDir      string // per-launch — recreated each start
	LogPath         string // RuntimeDir/tor.log
	TorrcPath       string // RuntimeDir/torrc
	DataDir         string // RuntimeDir/data
}

// NewLayout builds a Layout rooted at AnonLayer/tor.
func NewLayout(anonDir string) Layout {
	root := filepath.Join(anonDir, "tor")
	runtime := filepath.Join(root, "run")
	return Layout{
		Bin:           filepath.Join(root, "bin", "tor"),
		TorrcTemplate: filepath.Join(root, "etc", "torrc.template"),
		RuntimeDir:    runtime,
		LogPath:       filepath.Join(runtime, "tor.log"),
		TorrcPath:     filepath.Join(runtime, "torrc"),
		DataDir:       filepath.Join(runtime, "data"),
	}
}

// Spawned is what Start returns: the Managed process + the SOCKS port
// the launcher needs for the PAC.
type Spawned struct {
	Managed   *process.Managed
	SOCKSPort int
}

// Start renders a fresh torrc with random high ports, recreates the
// runtime dir, and prepares the Managed wrapper. Does NOT call
// Start() on the Managed — the caller registers it with the
// Supervisor first.
func Start(l Layout) (*Spawned, error) {
	socks, err := randomHighPort()
	if err != nil {
		return nil, err
	}
	control, err := randomHighPort()
	if err != nil {
		return nil, err
	}
	if err := os.RemoveAll(l.RuntimeDir); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("clear tor runtime: %w", err)
	}
	if err := os.MkdirAll(l.DataDir, 0o700); err != nil {
		return nil, err
	}
	tpl, err := os.ReadFile(l.TorrcTemplate)
	if err != nil {
		return nil, fmt.Errorf("read torrc template: %w", err)
	}
	rendered := strings.NewReplacer(
		"@@SOCKS_PORT@@", strconv.Itoa(socks),
		"@@CONTROL_PORT@@", strconv.Itoa(control),
		"@@DATA_DIR@@", l.DataDir,
	).Replace(string(tpl))
	if err := os.WriteFile(l.TorrcPath, []byte(rendered), 0o600); err != nil {
		return nil, fmt.Errorf("write torrc: %w", err)
	}

	logFile, err := os.OpenFile(l.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open tor log: %w", err)
	}
	cmd := exec.Command(l.Bin, "-f", l.TorrcPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	return &Spawned{
		Managed: &process.Managed{
			Name:        "tor",
			Cmd:         cmd,
			GracePeriod: 2 * time.Second,
			ReadyCheck:  socksReady(socks),
		},
		SOCKSPort: socks,
	}, nil
}

// socksReady polls TCP connect to 127.0.0.1:port. Matches the bash
// launcher's 10s/50-poll loop on tor SOCKS readiness.
func socksReady(port int) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		deadline := time.Now().Add(10 * time.Second)
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
			if err == nil {
				_ = c.Close()
				return nil
			}
			time.Sleep(200 * time.Millisecond)
		}
		return fmt.Errorf("tor SOCKS %s not ready", addr)
	}
}

// randomHighPort picks a random port in [30000, 60000). Matches the
// bash launcher's RANDOM-based port allocation range.
func randomHighPort() (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(30000))
	if err != nil {
		return 0, err
	}
	return 30000 + int(n.Int64()), nil
}
