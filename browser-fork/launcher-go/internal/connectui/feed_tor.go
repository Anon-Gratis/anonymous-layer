package connectui

import (
	"bufio"
	"context"
	"io"
	"os"
	"regexp"
	"strconv"
	"time"
)

// Matches lines like:
//
//	"Bootstrapped 5% (conn): Connecting to a relay"
//	"Bootstrapped 100% (done): Done"
//
// and extracts percentage + status word.
var torBootstrapRE = regexp.MustCompile(`Bootstrapped\s+(\d+)%[^:]*:\s*(.*)`)

// FeedTorLog tails tor's log file and pushes "tor" progress events to
// the connect UI as bootstrap proceeds. Exits when ctx is cancelled or
// the file emits "Bootstrapped 100%". Best-effort: silent on I/O error
// (the readiness probe in the tor package is the source of truth for
// "ready"; this feeder is just for visual progress).
func FeedTorLog(ctx context.Context, logPath string, s *Server) {
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
	s.Update("tor", 0, "starting")
	for {
		line, err := r.ReadString('\n')
		if line != "" {
			if m := torBootstrapRE.FindStringSubmatch(line); m != nil {
				pct, perr := strconv.Atoi(m[1])
				if perr == nil {
					label := m[2]
					if len(label) > 48 {
						label = label[:48]
					}
					s.Update("tor", pct, label)
					if pct >= 100 {
						return
					}
				}
			}
		}
		if err == io.EOF {
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
