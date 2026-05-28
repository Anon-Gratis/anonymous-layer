// Command anonymous — Go-language launcher for Anonymous Browser.
//
// The connection sequence (consensus → tor → bridge) is shown inside
// the browser itself, the way Tor Browser shows about:torconnect. We
// stand up a localhost HTTP server, launch the browser pointed at it,
// and run the boot sequence in the background — pushing progress to
// the browser via Server-Sent Events. When boot succeeds the page
// redirects to the configured homepage.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/anon-gratis/anonymous-layer/browser-fork/launcher-go/internal/bridge"
	"github.com/anon-gratis/anonymous-layer/browser-fork/launcher-go/internal/browser"
	"github.com/anon-gratis/anonymous-layer/browser-fork/launcher-go/internal/config"
	"github.com/anon-gratis/anonymous-layer/browser-fork/launcher-go/internal/connectui"
	"github.com/anon-gratis/anonymous-layer/browser-fork/launcher-go/internal/consensus"
	"github.com/anon-gratis/anonymous-layer/browser-fork/launcher-go/internal/pac"
	"github.com/anon-gratis/anonymous-layer/browser-fork/launcher-go/internal/process"
	"github.com/anon-gratis/anonymous-layer/browser-fork/launcher-go/internal/selfheal"
	"github.com/anon-gratis/anonymous-layer/browser-fork/launcher-go/internal/tor"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix("anonymous: ")

	installDir := flag.String("install-dir", "", "install root (default: dir containing this binary)")
	noUI := flag.Bool("no-ui", false, "disable the in-browser connect UI; log progress to stderr only")
	flag.Parse()

	if *installDir == "" {
		exe, err := os.Executable()
		if err != nil {
			die("locate self: %v", err)
		}
		*installDir = filepath.Dir(exe)
	}

	cfg, err := config.Load(*installDir)
	if err != nil {
		die("config: %v", err)
	}

	// Self-heal: fix policies.json placeholder + clear stale Firefox
	// profile locks before anything else launches. Idempotent.
	selfheal.RunAll(cfg.InstallDir, cfg.BrowserRoot, cfg.ResourceRoot)

	sup := &process.Supervisor{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	installSignalHandler(cancel)
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		sup.Shutdown(shutdownCtx)
	}()

	homepage := fmt.Sprintf("http://%s:%d/", cfg.BridgeHost, cfg.BridgePort)

	// Start the in-browser connect UI server (unless --no-ui).
	var ui *connectui.Server
	if !*noUI {
		ui, err = connectui.Start(homepage)
		if err != nil {
			die("connect UI: %v", err)
		}
		defer func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer shutdownCancel()
			_ = ui.Shutdown(shutdownCtx)
		}()
		log.Printf("connect UI: %s", ui.URL())
	}

	// Browser comes up FIRST — pointed at the connect page. The boot
	// orchestration runs concurrently and pushes progress over SSE.
	browserArgs := flag.Args()
	if ui != nil {
		browserArgs = append([]string{ui.URL()}, browserArgs...)
	}
	br, err := browser.Launch(cfg.BrowserRoot, browserArgs)
	if err != nil {
		die("browser prepare: %v", err)
	}
	sup.Add(br)
	if err := br.Start(); err != nil {
		die("browser start: %v", err)
	}
	log.Printf("browser launched")

	// Boot orchestration runs concurrently with the browser process.
	// On success it calls ui.Finish() — the page redirects to homepage.
	// On failure it calls ui.Fail() — the page shows an error state.
	startupDone := make(chan error, 1)
	go func() {
		err := runBoot(ctx, cfg, sup, ui)
		if err != nil {
			log.Printf("startup failed: %v", err)
			if ui != nil {
				ui.Fail(err.Error())
			}
		} else if ui != nil {
			ui.Finish()
		}
		startupDone <- err
	}()

	if err := browser.WaitExit(ctx, br); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("browser exited: %v", err)
	}
	log.Printf("browser exited; shutting down support processes")

	// Best-effort: drain the boot goroutine before tearing things down.
	select {
	case <-startupDone:
	case <-time.After(2 * time.Second):
	}
}

// runBoot does the consensus → tor → bridge sequence, pushing progress
// events into the connect UI (ui may be nil under --no-ui, in which
// case progress is stderr-only via the normal log lines).
func runBoot(ctx context.Context, cfg *config.Config, sup *process.Supervisor, ui *connectui.Server) error {
	update := func(name string, pct int, label string) {
		if ui != nil {
			ui.Update(name, pct, label)
		}
		if label == "" {
			log.Printf("progress: %-8s %3d%%", name, pct)
		} else {
			log.Printf("progress: %-8s %3d%% — %s", name, pct, label)
		}
	}

	// 1. Consensus refresh (skipped in CONNECT mode).
	if !cfg.IsConnectMode() {
		update("consensus", 0, "fetching from DA")
		if err := consensus.Refresh(ctx, cfg.DAURLs, cfg.Consensus); err != nil {
			update("consensus", 100, "failed: "+err.Error())
			return fmt.Errorf("consensus: %w", err)
		}
		update("consensus", 100, "fresh")
	}

	// 2. Tor (skipped if ANON_DISABLE_TOR or CONNECT mode).
	torSocks := pac.SentinelPort
	if !cfg.DisableTor && !cfg.IsConnectMode() {
		torLayout := tor.NewLayout(cfg.AnonDir)
		update("tor", 0, "preparing")
		torP, err := tor.Start(torLayout)
		if err != nil {
			return fmt.Errorf("tor prepare: %w", err)
		}
		sup.Add(torP.Managed)
		if err := torP.Managed.Start(); err != nil {
			return fmt.Errorf("tor start: %w", err)
		}
		if ui != nil {
			go connectui.FeedTorLog(ctx, torLayout.LogPath, ui)
		}

		readyCtx, cancelReady := context.WithTimeout(ctx, 60*time.Second)
		err = torP.Managed.WaitReady(readyCtx)
		cancelReady()
		if err != nil {
			return fmt.Errorf("tor not ready: %w", err)
		}
		update("tor", 100, "ready")
		torSocks = torP.SOCKSPort
		log.Printf("tor SOCKS: 127.0.0.1:%d", torSocks)

		pacTemplate := filepath.Join(torLayout.RuntimeDir, "..", "etc", "anon.pac.template")
		pacDest := filepath.Join(torLayout.RuntimeDir, "anon.pac")
		if _, err := os.Stat(pacTemplate); err == nil {
			if err := pac.Render(pacTemplate, pacDest, torSocks, pac.SentinelPort); err != nil {
				log.Printf("warning: PAC render failed: %v", err)
			}
		}
	}

	// 3. Bridge.
	brLayout := bridge.NewLayout(cfg.AnonDir)
	update("bridge", 0, "preparing")
	brP, attached, err := bridge.Start(brLayout, cfg)
	if err != nil {
		return fmt.Errorf("bridge prepare: %w", err)
	}
	sup.Add(brP)
	if attached {
		update("bridge", 100, "attached (already running)")
		log.Printf("attached to existing bridge on %s:%d", cfg.BridgeHost, cfg.BridgePort)
	} else {
		if err := brP.Start(); err != nil {
			return fmt.Errorf("bridge start: %w", err)
		}
		update("bridge", 50, "starting")
		readyCtx, cancelReady := context.WithTimeout(ctx, 65*time.Second)
		err := brP.WaitReady(readyCtx)
		cancelReady()
		if err != nil {
			return fmt.Errorf("bridge not ready: %w", err)
		}
		update("bridge", 100, "ready")
		log.Printf("bridge ready on %s:%d", cfg.BridgeHost, cfg.BridgePort)
	}
	return nil
}

func installSignalHandler(cancel context.CancelFunc) {
	// Explicitly ignore SIGHUP. Without this, closing the terminal
	// that started us (or an SSH disconnect, or systemd-logind
	// session end) sends SIGHUP to the launcher → cancel() → connect
	// UI server shuts down → orphaned anonymous.real keeps running
	// with a stale connect-UI URL in its tabs → user sees
	// "Unable to connect" on the next tab restore.
	//
	// The engine (anonymous.real) detaches from the controlling TTY
	// itself, so the right move is: let it run, ignore SIGHUP.
	signal.Ignore(syscall.SIGHUP)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.Printf("received %v, shutting down", sig)
		cancel()
	}()
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "anonymous: "+format+"\n", args...)
	os.Exit(1)
}
