// Package splash provides the boot-time progress window.
//
// The Backend interface is implemented by:
//   - webviewBackend (Linux/Win/Mac via webview/webview_go)
//   - logBackend (stderr fallback when no display server or CGo)
//
// Selection is done by New() at runtime based on DISPLAY availability.
package splash

import (
	"log"
	"os"
)

// Backend is what main.go talks to. Methods are safe to call from any
// goroutine — implementations queue work to the right thread.
type Backend interface {
	// Run blocks until the splash closes (all bars at 100 or window
	// closed). For log backend, returns immediately.
	Run()
	// Update sets a named progress bar's percent and (optional) label.
	// pct ≥ 100 marks the bar done; once all bars are done the splash
	// auto-closes.
	Update(name string, pct int, label string)
	// Done closes the splash regardless of bar state.
	Done()
}

// New selects the best available backend. webview if we're on a
// graphical session and CGo is available; logBackend otherwise.
func New() Backend {
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		log.Printf("splash: no display server; falling back to log backend")
		return &logBackend{}
	}
	wb, err := newWebview()
	if err != nil {
		log.Printf("splash: webview init failed (%v); falling back to log backend", err)
		return &logBackend{}
	}
	return wb
}
