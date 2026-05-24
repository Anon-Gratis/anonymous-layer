// Package consensus mirrors the bash launcher's fetch_consensus():
// try each DA HTTPS endpoint in order, first 200 wins, atomic
// replace. If every DA fails, leave the cached file in place
// (stale-but-cached beats hard failure).
package consensus

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Refresh tries each comma-separated DA URL in order. Returns nil on
// the first successful fetch+write; returns an error only if no DA
// succeeds AND no cached file exists at dest.
func Refresh(ctx context.Context, daURLs, dest string) error {
	if dest == "" {
		return nil
	}
	urls := splitAndClean(daURLs)
	if len(urls) == 0 {
		return nil
	}
	client := &http.Client{Timeout: 15 * time.Second}
	for _, u := range urls {
		full := strings.TrimRight(u, "/") + "/consensus.bin"
		log.Printf("refresh: fetching %s", full)
		body, err := fetchOnce(ctx, client, full)
		if err != nil {
			log.Printf("refresh: %s failed: %v", full, err)
			continue
		}
		if err := atomicWrite(dest, body); err != nil {
			log.Printf("refresh: write to %s failed: %v", dest, err)
			continue
		}
		log.Printf("refresh: wrote %d bytes from %s", len(body), full)
		return nil
	}
	// All DAs failed — only fatal if we have no cached file.
	if _, err := os.Stat(dest); err == nil {
		log.Printf("refresh: all DAs unreachable; using cached %s", dest)
		return nil
	}
	return fmt.Errorf("no DA reachable and no cached consensus at %s", dest)
}

func fetchOnce(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "anon-launcher/1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("empty body")
	}
	return body, nil
}

func atomicWrite(dest string, data []byte) error {
	dir := filepath.Dir(dest)
	tmp, err := os.CreateTemp(dir, ".consensus.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op if rename succeeded
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, dest)
}

func splitAndClean(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
