package splash

import (
	"bufio"
	"context"
	"io"
	"os"
	"regexp"
	"strconv"
	"time"
)

// Matches the bash splash_feed_tor heuristic: greps lines like
//   "Bootstrapped 5% (conn): Connecting to a relay"
//   "Bootstrapped 100% (done): Done"
// and extracts the percentage + status word.
var torBootstrapRE = regexp.MustCompile(`Bootstrapped\s+(\d+)%[^:]*:\s*(.*)`)

// FeedTorLog tails the given log file and pushes "tor" progress events
// to the backend as tor bootstraps. Exits when ctx is cancelled or the
// file emits Bootstrapped 100%. Best-effort: silent on any I/O error
// (the readiness probe in tor package is the source of truth for
// "ready" — the splash feeder is just visual flavor).
func FeedTorLog(ctx context.Context, logPath string, b Backend) {
	// Wait briefly for the log to appear if tor hasn't started yet.
	for attempt := 0; attempt < 50; attempt++ {
		if _, err := os.Stat(logPath); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	f, err := os.Open(logPath)
	if err != nil {
		return
	}
	defer f.Close()
	r := bufio.NewReader(f)
	b.Update("tor", 0, "starting")
	for {
		line, err := r.ReadString('\n')
		if line != "" {
			if m := torBootstrapRE.FindStringSubmatch(line); m != nil {
				pct, perr := strconv.Atoi(m[1])
				if perr == nil {
					label := m[2]
					if len(label) > 32 {
						label = label[:32]
					}
					b.Update("tor", pct, label)
					if pct >= 100 {
						return
					}
				}
			}
		}
		if err == io.EOF {
			// Hit the tail; wait briefly and continue (tail -F semantics).
			select {
			case <-ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		if err != nil {
			return
		}
	}
}
