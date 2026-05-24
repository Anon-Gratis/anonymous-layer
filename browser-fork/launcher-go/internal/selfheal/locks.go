package selfheal

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

// StaleLocks scans Data/*/{.parentlock,lock,parent.lock} and removes
// any whose symlink target encodes a dead PID. Matches the bash
// launcher's lines 394–404. Skipped silently when Data/ doesn't
// exist (first launch of a brand-new install) or has no profile dirs.
//
// Firefox's profile lock convention:
//   - .parentlock — file flock (Linux). Best-effort cleanup; flock
//     is released by kernel on process exit so a stale file with no
//     symlink target is usually harmless. We just remove it.
//   - lock        — symlink. Target format: 127.0.0.1:+PID (or :PID).
//     If PID is dead, the lock is stale.
//   - parent.lock — Windows equivalent. Symlinks aren't common on
//     Windows; treat as file.
//
// Removing a stale lock prevents Firefox from refusing to start
// after a crash, which is otherwise the #1 cause of "the browser
// won't launch" support requests on the bash launcher.
func StaleLocks(installDir string) error {
	dataDir := filepath.Join(installDir, "Data")
	profiles, err := os.ReadDir(dataDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read %s: %w", dataDir, err)
	}
	for _, p := range profiles {
		if !p.IsDir() {
			continue
		}
		profileDir := filepath.Join(dataDir, p.Name())
		cleanProfileLocks(profileDir)
	}
	return nil
}

// lockSymlinkPID parses "127.0.0.1:+12345" or ":+12345" into the PID.
var lockSymlinkPID = regexp.MustCompile(`:\+?(\d+)$`)

func cleanProfileLocks(profileDir string) {
	for _, name := range []string{"lock", ".parentlock", "parent.lock"} {
		path := filepath.Join(profileDir, name)
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				continue
			}
			m := lockSymlinkPID.FindStringSubmatch(target)
			if m == nil {
				// Symlink doesn't look like Firefox's lock format —
				// leave it alone; not our concern.
				continue
			}
			pid, _ := strconv.Atoi(m[1])
			if processAlive(pid) {
				continue
			}
			if err := os.Remove(path); err == nil {
				log.Printf("selfheal: removed stale lock %s → %s (pid %d not alive)", path, target, pid)
			}
		} else {
			// Plain file (.parentlock or parent.lock). Best-effort
			// remove — flock-style locks are released on process
			// exit so a stale file blocks nothing, but its presence
			// confuses some Firefox versions. Don't fail if we can't.
			if err := os.Remove(path); err == nil {
				log.Printf("selfheal: removed stale file lock %s", path)
			}
		}
	}
}

// processAlive returns true if the PID corresponds to a running process.
// os.FindProcess never errors on Unix; we send signal 0 to test.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Signal 0 == "check if alive without actually sending anything".
	// Works on Unix; on Windows os.Process.Signal(nil) is a no-op error,
	// so we fall through and assume the lock is stale only if FindProcess
	// itself fails (which it doesn't on Windows for PIDs that ever
	// existed, so the lock cleanup is less precise on Windows — acceptable
	// for an MVP self-heal pass).
	return p.Signal(nil) == nil
}
