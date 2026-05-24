// Package browser locates and exec's the bundled Firefox-fork engine.
// Exits cleanly when the engine exits — the launcher's signal handlers
// take care of the rest.
package browser

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/anon-gratis/anonymous-layer/browser-fork/launcher-go/internal/process"
)

// Launch finds the engine entry point appropriate for the host OS and
// starts it with the given passthrough args. Returns a Managed wrapper —
// the caller registers it with the Supervisor and waits for it to exit.
//
// Engine entry points per OS:
//
//	Linux/BSD : Browser/start-anonymous (shell script in the Mullvad tree)
//	macOS     : Browser/Anonymous.app/Contents/MacOS/firefox (planned;
//	            actual layout TBD when the macOS .dmg path lands)
//	Windows   : Browser/firefox.exe (the engine binary directly — no
//	            wrapper script in the Mullvad Windows distribution)
func Launch(browserRoot string, args []string) (*process.Managed, error) {
	launcher, fullArgs, err := pickEngine(browserRoot, args)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(launcher, fullArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return &process.Managed{
		Name:        "browser",
		Cmd:         cmd,
		GracePeriod: 3 * time.Second,
		// No readiness check — once it launches we wait for it to
		// exit (user closing the browser is the shutdown signal).
	}, nil
}

// pickEngine returns the executable path and final argv for the host OS.
func pickEngine(browserRoot string, passthrough []string) (string, []string, error) {
	switch runtime.GOOS {
	case "windows":
		// Mullvad's Windows distro ships `mullvadbrowser.exe`; vanilla
		// Firefox ships `firefox.exe`. Try both in order so we work
		// with either upstream without script changes.
		candidates := []string{
			filepath.Join(browserRoot, "mullvadbrowser.exe"),
			filepath.Join(browserRoot, "firefox.exe"),
		}
		for _, c := range candidates {
			if isExecutable(c) {
				// No X11 wm-class on Windows; pass passthrough straight through.
				return c, passthrough, nil
			}
		}
		return "", nil, fmt.Errorf("no Windows engine binary found in %v", candidates)

	case "darwin":
		// In a Mac .app bundle the launcher lives at
		// Contents/MacOS/anonymous and the original engine binary
		// (firefox / mullvadbrowser / …) also lives in Contents/MacOS.
		// The repackage script writes the original binary's name to
		// .engine-binary in the Resources dir so we don't have to
		// hardcode upstream naming choices.
		//
		// macOS-aware browserRoot from config: $Contents/Resources/Browser.
		// MacOS dir == Contents/MacOS, sibling of Resources.
		macOSDir := filepath.Join(browserRoot, "..", "..", "MacOS")
		engineNames := readEngineHint(filepath.Join(browserRoot, "..", ".engine-binary"))
		for _, name := range engineNames {
			c := filepath.Join(macOSDir, name)
			if isExecutable(c) {
				return c, passthrough, nil
			}
		}
		// Last-resort fallbacks — search the MacOS dir for known names.
		for _, c := range []string{
			filepath.Join(macOSDir, "firefox"),
			filepath.Join(macOSDir, "mullvadbrowser"),
		} {
			if isExecutable(c) {
				return c, passthrough, nil
			}
		}
		return "", nil, fmt.Errorf("no macOS engine binary found in %s (tried %v)", macOSDir, engineNames)

	default:
		// Linux / *BSD — wrapper shell script with the X11 class hints.
		candidates := []string{
			filepath.Join(browserRoot, "start-anonymous"),
			filepath.Join(filepath.Dir(browserRoot), "start-anonymous"),
		}
		for _, c := range candidates {
			if isExecutable(c) {
				args := append([]string{"--class", "Anonymous", "--name", "Anonymous"}, passthrough...)
				return c, args, nil
			}
		}
		return "", nil, fmt.Errorf("no Unix engine launcher found in %v", candidates)
	}
}

// readEngineHint reads the single-line .engine-binary file written by
// repackage-mullvad-macos.sh and returns it as a 1-element slice of
// candidate names. Returns nil if the file doesn't exist or is empty —
// the caller falls back to a hardcoded candidate list.
func readEngineHint(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	name := strings.TrimSpace(string(data))
	if name == "" {
		return nil
	}
	return []string{name}
}

func isExecutable(p string) bool {
	st, err := os.Stat(p)
	if err != nil {
		return false
	}
	if st.IsDir() {
		return false
	}
	// On Windows we can't usefully check the perm bit; the .stat suffices.
	if runtime.GOOS == "windows" {
		return true
	}
	return st.Mode().Perm()&0o111 != 0
}

// WaitExit blocks until the browser process exits, returning its
// exit error (or nil for clean exit).
func WaitExit(ctx context.Context, m *process.Managed) error {
	if m.Cmd == nil || m.Cmd.Process == nil {
		return fmt.Errorf("browser was not started")
	}
	done := make(chan error, 1)
	go func() { done <- m.Cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
