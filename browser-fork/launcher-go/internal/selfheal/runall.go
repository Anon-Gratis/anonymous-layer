package selfheal

import (
	"log"
)

// RunAll runs every cross-platform self-heal step in safe order:
// stale-lock cleanup first (so Firefox can launch), then policies.json
// (so Firefox sees a valid policy on first load).
//
// Each step is idempotent and logs only on actually-made changes;
// a healthy install produces no output.
func RunAll(installDir, browserRoot, resourceRoot string) {
	if err := StaleLocks(installDir); err != nil {
		log.Printf("selfheal: stale-lock cleanup: %v", err)
	}
	if err := Policies(browserRoot, resourceRoot); err != nil {
		log.Printf("selfheal: policies.json: %v", err)
	}
}
