// Package connectui serves the in-browser connection UI.
//
// On boot the launcher starts an HTTP server on 127.0.0.1:<random-port>
// and points the browser at "/". The page is fully server-side rendered
// with a <meta http-equiv="refresh"> polling tag, so it works even when
// JavaScript is disabled (e.g. Tor-Browser "Safest" security level).
// When boot finishes the next refresh returns a 0-second meta-refresh
// to the configured homepage.
//
// PAC routes 127.0.0.1 to DIRECT, so this server is reachable even
// before tor / bridge are up.
package connectui

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

//go:embed index.html
var assets embed.FS

// Event is one progress update stored on the server.
type Event struct {
	Name  string // e.g. "consensus", "tor", "bridge"
	Pct   int    // 0..100
	Label string // optional human-readable status
}

// Server is the connect UI HTTP server.
type Server struct {
	url      string         // base URL clients should hit, e.g. http://127.0.0.1:51234/
	homepage string         // where to redirect when boot completes
	ln       net.Listener
	srv      *http.Server

	mu       sync.Mutex
	state    map[string]Event // latest event per bar name
	order    []string         // insertion order of bar names
	finished bool
	fatal    string
	tpl      *template.Template
}

// PollInterval is how often the connect page reloads itself while
// boot is in progress. Server-side rendering means each reload picks
// up the latest progress.
const PollInterval = 1 * time.Second

// Start binds a localhost listener on a free port and begins serving.
// homepage is the URL the page redirects to once Finish() is called.
// Returns the Server (call Server.URL to get the connect-page URL).
func Start(homepage string) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	raw, err := assets.ReadFile("index.html")
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("read index.html: %w", err)
	}
	tpl, err := template.New("index").Parse(string(raw))
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("parse index.html: %w", err)
	}
	s := &Server{
		url:      fmt.Sprintf("http://127.0.0.1:%d/", port),
		homepage: homepage,
		ln:       ln,
		state:    make(map[string]Event),
		tpl:      tpl,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("connectui: serve: %v", err)
		}
	}()
	return s, nil
}

// URL is the base URL the browser should open.
func (s *Server) URL() string { return s.url }

// Update stores a progress event so the next page render reflects it.
// Safe from any goroutine.
func (s *Server) Update(name string, pct int, label string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, seen := s.state[name]; !seen {
		s.order = append(s.order, name)
	}
	s.state[name] = Event{Name: name, Pct: clampPct(pct), Label: label}
}

// Fail marks the boot sequence as failed. The next page render shows
// the error message and stops the meta-refresh polling. After Fail,
// Finish becomes a no-op.
func (s *Server) Fail(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished {
		return
	}
	s.fatal = msg
}

// Finish marks boot complete. The next page render returns a
// 0-second meta-refresh to the homepage. Idempotent.
func (s *Server) Finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished || s.fatal != "" {
		return
	}
	s.finished = true
}

// Shutdown stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// viewModel is the data passed to index.html on each render.
type viewModel struct {
	Homepage     string
	Bars         []Event
	Done         bool
	Fatal        string
	Title        string
	Subtitle     string
	PollSeconds  int
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	vm := viewModel{
		Homepage:    s.homepage,
		Done:        s.finished,
		Fatal:       s.fatal,
		PollSeconds: int(PollInterval / time.Second),
	}
	// Render bars in insertion order. If nothing has been reported
	// yet, seed the three expected rows so the layout doesn't pop
	// in once the first event arrives.
	if len(s.order) == 0 {
		vm.Bars = []Event{
			{Name: "consensus", Pct: 0, Label: "waiting…"},
			{Name: "tor", Pct: 0, Label: "waiting…"},
			{Name: "bridge", Pct: 0, Label: "waiting…"},
		}
	} else {
		for _, name := range s.order {
			vm.Bars = append(vm.Bars, s.state[name])
		}
	}
	s.mu.Unlock()

	switch {
	case vm.Done:
		vm.Title = "CONNECTED"
		vm.Subtitle = "OPENING HOMEPAGE"
	case vm.Fatal != "":
		vm.Title = "CONNECTION FAILED"
		vm.Subtitle = "RESTART THE BROWSER TO TRY AGAIN"
	default:
		vm.Title = "// ANON BROWSER"
		vm.Subtitle = "ESTABLISHING ANONYMOUS CIRCUIT"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.tpl.Execute(w, vm); err != nil {
		log.Printf("connectui: template execute: %v", err)
	}
}

func clampPct(p int) int {
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return p
}
