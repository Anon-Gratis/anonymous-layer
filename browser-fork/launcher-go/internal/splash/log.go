package splash

import (
	"log"
	"sync"
)

// logBackend is the no-window fallback. It prints "splash: NAME PCT% LABEL"
// to stderr on each Update and is a no-op for Run/Done.
type logBackend struct {
	mu   sync.Mutex
	last map[string]int // suppress duplicate same-percent updates
}

func (b *logBackend) Run() { /* no-op; nothing to block on */ }

func (b *logBackend) Update(name string, pct int, label string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last == nil {
		b.last = make(map[string]int)
	}
	if prev, ok := b.last[name]; ok && prev == pct {
		return
	}
	b.last[name] = pct
	if label == "" {
		log.Printf("splash: %-8s %3d%%", name, pct)
	} else {
		log.Printf("splash: %-8s %3d%% — %s", name, pct, label)
	}
}

func (b *logBackend) Done() { log.Printf("splash: done") }
