//go:build cgo

package splash

import (
	_ "embed"
	"fmt"
	"log"
	"sync"

	webview "github.com/webview/webview_go"
)

//go:embed index.html
var splashHTML string

// webviewBackend embeds a small windowed splash via webview/webview_go.
// Linux uses WebKitGTK, Windows WebView2, macOS WebKit. CGo dep — needs
// the corresponding dev headers at build time.
type webviewBackend struct {
	w        webview.WebView
	mu       sync.Mutex
	closed   bool
	doneCh   chan struct{}
}

func newWebview() (Backend, error) {
	// Create the window synchronously here, but DON'T enter the event
	// loop yet (that happens in Run()). Catch a panic if webview fails
	// to init (rare but possible: missing libwebkit2gtk runtime).
	var b *webviewBackend
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("splash: webview.New panicked: %v", r)
			}
		}()
		w := webview.New(false)
		if w == nil {
			return
		}
		w.SetTitle("// ANON BROWSER")
		w.SetSize(560, 240, webview.HintFixed)
		b = &webviewBackend{w: w, doneCh: make(chan struct{})}
	}()
	if b == nil {
		return nil, fmt.Errorf("webview.New returned nil")
	}
	// Bind splashDone so the JS can request window close from the
	// "all bars at 100" handler.
	if err := b.w.Bind("splashDone", func() {
		b.Done()
	}); err != nil {
		return nil, fmt.Errorf("bind splashDone: %w", err)
	}
	b.w.SetHtml(splashHTML)
	return b, nil
}

// Run blocks on the webview event loop. Returns when Done() is called
// or the user closes the window. MUST be called on the main goroutine
// (GTK requirement).
func (b *webviewBackend) Run() {
	// webview.Run blocks until Terminate is called.
	b.w.Run()
	close(b.doneCh)
}

// Update schedules a JS call into the splash via webview.Dispatch
// (which marshals onto the GTK main thread). Safe from any goroutine.
func (b *webviewBackend) Update(name string, pct int, label string) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.mu.Unlock()
	w := b.w
	w.Dispatch(func() {
		// Escape via JSON literal to avoid having to hand-escape.
		js := fmt.Sprintf("window.anonProgress(%q, %d, %q);", name, pct, label)
		w.Eval(js)
	})
}

// Done dismisses the splash. Idempotent and safe from any goroutine.
// Internally Dispatches Terminate onto the event loop thread.
func (b *webviewBackend) Done() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	b.mu.Unlock()
	w := b.w
	w.Dispatch(func() { w.Terminate() })
}
