// Command anonymous — Go-language launcher for Anonymous Browser.
//
// Phase 2 scope: MVP (consensus + tor + bridge + browser, attach-mode)
// plus a webview-based splash UI with stderr fallback. No i2pd, no
// bwrap, no --volatile, no --register-app yet (phase 3).
//
// The webview library REQUIRES the main goroutine for its event loop
// (GTK constraint). So main() splits into:
//   - a "work" goroutine that runs the boot sequence and feeds splash
//   - the main goroutine that blocks on splash.Run()
// When the work goroutine finishes (success or failure), it signals
// the splash to dismiss; main() then proceeds to exec the browser.
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
	"github.com/anon-gratis/anonymous-layer/browser-fork/launcher-go/internal/consensus"
	"github.com/anon-gratis/anonymous-layer/browser-fork/launcher-go/internal/pac"
	"github.com/anon-gratis/anonymous-layer/browser-fork/launcher-go/internal/process"
	"github.com/anon-gratis/anonymous-layer/browser-fork/launcher-go/internal/selfheal"
	"github.com/anon-gratis/anonymous-layer/browser-fork/launcher-go/internal/splash"
	"github.com/anon-gratis/anonymous-layer/browser-fork/launcher-go/internal/tor"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix("anonymous: ")

	installDir := flag.String("install-dir", "", "install root (default: dir containing this binary)")
	noSplash := flag.Bool("no-splash", false, "disable the windowed splash; use stderr only")
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
	// profile locks before anything else launches. Idempotent — a
	// healthy install produces no log output.
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

	// Pick the splash backend. If --no-splash, force the log fallback.
	var sp splash.Backend
	if *noSplash {
		sp = &noopBackend{}
	} else {
		sp = splash.New()
	}

	// The work goroutine does boot orchestration AND fires sp.Done()
	// when finished. The main goroutine blocks on sp.Run() until then.
	startupDone := make(chan error, 1)
	go func() {
		err := runBoot(ctx, cfg, sup, sp)
		// Whatever happened, dismiss the splash so main can move on.
		sp.Done()
		startupDone <- err
	}()

	sp.Run() // returns when sp.Done() is called or window closed

	// Reap the work goroutine's result.
	if err := <-startupDone; err != nil {
		die("startup: %v", err)
	}

	// 4. Browser — passthrough args after our own flags.
	br, err := browser.Launch(cfg.BrowserRoot, flag.Args())
	if err != nil {
		die("browser prepare: %v", err)
	}
	sup.Add(br)
	if err := br.Start(); err != nil {
		die("browser start: %v", err)
	}
	log.Printf("browser launched")

	if err := browser.WaitExit(ctx, br); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("browser exited: %v", err)
	}
	log.Printf("browser exited; shutting down support processes")
}

// runBoot does the consensus → tor → bridge sequence, updating the
// splash as it goes. Runs on a worker goroutine (NOT the main
// goroutine — GTK can't share). Returns the first fatal error, or
// nil on success.
func runBoot(ctx context.Context, cfg *config.Config, sup *process.Supervisor, sp splash.Backend) error {
	// 1. Consensus refresh (skipped in CONNECT mode).
	if !cfg.IsConnectMode() {
		sp.Update("consensus", 0, "fetching from DA")
		if err := consensus.Refresh(ctx, cfg.DAURLs, cfg.Consensus); err != nil {
			sp.Update("consensus", 100, "failed: "+err.Error())
			return fmt.Errorf("consensus: %w", err)
		}
		sp.Update("consensus", 100, "fresh")
	}

	// 2. Tor (skipped if ANON_DISABLE_TOR or CONNECT mode).
	torSocks := pac.SentinelPort
	if !cfg.DisableTor && !cfg.IsConnectMode() {
		torLayout := tor.NewLayout(cfg.AnonDir)
		sp.Update("tor", 0, "preparing")
		torP, err := tor.Start(torLayout)
		if err != nil {
			return fmt.Errorf("tor prepare: %w", err)
		}
		sup.Add(torP.Managed)
		if err := torP.Managed.Start(); err != nil {
			return fmt.Errorf("tor start: %w", err)
		}
		// Tail tor.log on a goroutine — sends fine-grained Bootstrapped %.
		go splash.FeedTorLog(ctx, torLayout.LogPath, sp)

		readyCtx, cancelReady := context.WithTimeout(ctx, 60*time.Second)
		err = torP.Managed.WaitReady(readyCtx)
		cancelReady()
		if err != nil {
			return fmt.Errorf("tor not ready: %w", err)
		}
		// Force the bar to 100 in case the tailer didn't see the
		// final Bootstrapped 100% line (e.g., tor wrote it before we
		// opened the file).
		sp.Update("tor", 100, "ready")
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
	sp.Update("bridge", 0, "preparing")
	brP, attached, err := bridge.Start(brLayout, cfg)
	if err != nil {
		return fmt.Errorf("bridge prepare: %w", err)
	}
	sup.Add(brP)
	if attached {
		sp.Update("bridge", 100, "attached (already running)")
		log.Printf("attached to existing bridge on %s:%d", cfg.BridgeHost, cfg.BridgePort)
	} else {
		if err := brP.Start(); err != nil {
			return fmt.Errorf("bridge start: %w", err)
		}
		sp.Update("bridge", 50, "starting")
		readyCtx, cancelReady := context.WithTimeout(ctx, 65*time.Second)
		err := brP.WaitReady(readyCtx)
		cancelReady()
		if err != nil {
			return fmt.Errorf("bridge not ready: %w", err)
		}
		sp.Update("bridge", 100, "ready")
		log.Printf("bridge ready on %s:%d", cfg.BridgeHost, cfg.BridgePort)
	}
	return nil
}

// noopBackend is the --no-splash backend: do nothing, never block.
type noopBackend struct{}

func (noopBackend) Run()                                   {}
func (noopBackend) Update(name string, pct int, label string) {}
func (noopBackend) Done()                                  {}

func installSignalHandler(cancel context.CancelFunc) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
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
