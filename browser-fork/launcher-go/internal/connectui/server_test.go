package connectui

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// fetch GETs s.URL() and returns the body as a string.
func fetch(t *testing.T, s *Server) string {
	t.Helper()
	resp, err := http.Get(s.URL())
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}

// TestInitialRender — on a fresh server the page should pre-seed the
// three expected bars at 0%, include the polling meta-refresh, and
// embed the homepage URL nowhere yet (it only appears in the refresh
// destination after Finish()).
func TestInitialRender(t *testing.T) {
	s, err := Start("http://homepage.test/")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Shutdown(context.Background())

	body := fetch(t, s)
	if !strings.Contains(body, "ANON BROWSER") {
		t.Errorf("missing header")
	}
	if !strings.Contains(body, `http-equiv="refresh" content="1"`) {
		t.Errorf("missing polling meta-refresh; body:\n%s", body)
	}
	for _, name := range []string{"consensus", "tor", "bridge"} {
		if !strings.Contains(body, name) {
			t.Errorf("missing pre-seeded bar %q", name)
		}
	}
	// Homepage URL must NOT yet appear as a refresh target (we're not done).
	if strings.Contains(body, "0; url=http://homepage.test/") {
		t.Errorf("page shouldn't redirect before Finish")
	}
}

// TestUpdateThenRender — after Update() calls, the next render shows
// the new percent + label.
func TestUpdateThenRender(t *testing.T) {
	s, err := Start("http://x/")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Shutdown(context.Background())

	s.Update("consensus", 100, "fresh")
	s.Update("tor", 42, "Bootstrapped 42%")
	s.Update("bridge", 50, "starting")

	body := fetch(t, s)

	// Percentages appear in the bar fills (style="width: 42%") AND in
	// the <span class="pct">42%</span> spans. Either form is fine for
	// the test; we just want evidence the value made it through.
	for _, want := range []string{"width: 100%", "width: 42%", "width: 50%", "fresh", "Bootstrapped 42%", "starting"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

// TestFinishYieldsRedirect — after Finish(), the page returns a
// 0-second meta-refresh to the homepage.
func TestFinishYieldsRedirect(t *testing.T) {
	s, err := Start("http://homepage.test/path?q=1")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Shutdown(context.Background())

	s.Update("consensus", 100, "fresh")
	s.Update("tor", 100, "ready")
	s.Update("bridge", 100, "ready")
	s.Finish()

	body := fetch(t, s)
	// html/template HTML-escapes the URL inside an attribute (=> &amp;
	// etc.), but ?q=1 should still be visible literally.
	if !strings.Contains(body, "0; url=http://homepage.test/path?q=1") {
		t.Errorf("missing 0s redirect to homepage; body:\n%s", body)
	}
	if !strings.Contains(body, "CONNECTED") {
		t.Errorf("body missing CONNECTED state")
	}
	if strings.Contains(body, `content="1"`) {
		t.Errorf("page should not still be polling after Finish")
	}
}

// TestFailSuppressesFinish — after Fail(), Finish() is a no-op and
// the page shows the error.
func TestFailSuppressesFinish(t *testing.T) {
	s, err := Start("http://x/")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Shutdown(context.Background())

	s.Update("consensus", 100, "fresh")
	s.Fail("tor refused to bootstrap: timeout after 60s")
	s.Finish() // must be a no-op after Fail

	body := fetch(t, s)
	if !strings.Contains(body, "CONNECTION FAILED") {
		t.Errorf("body missing fatal state")
	}
	if !strings.Contains(body, "tor refused to bootstrap") {
		t.Errorf("body missing fatal message")
	}
	if strings.Contains(body, "0; url=") {
		t.Errorf("page should not redirect after Fail")
	}
	if strings.Contains(body, `http-equiv="refresh"`) {
		t.Errorf("page should not poll after Fail")
	}
}
