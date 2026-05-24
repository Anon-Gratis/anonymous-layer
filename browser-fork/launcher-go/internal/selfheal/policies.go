// Package selfheal performs the per-launch fixups the bash launcher
// does to keep an install working after it's been moved, re-extracted,
// or freshly unpacked from a portable archive.
//
// Mirrors anon-browser.launcher.sh:
//   - policies.json `@@INSTALL_DIR@@` placeholder → real install dir
//   - stale-lock cleanup on Data/*/.parentlock, lock, parent.lock
//
// All operations are idempotent — running them on an already-healed
// install is a no-op. Safe to call on every launch.
package selfheal

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const installDirPlaceholder = "@@INSTALL_DIR@@"

// Policies substitutes `@@INSTALL_DIR@@` in policies.json with the
// real install dir, converting to file:// URI conventions on Windows.
// Required because the Win/Mac repackage scripts can't know the
// user's extract path at build time — they ship the placeholder and
// the launcher fixes it on first launch.
//
// On Linux the bash launcher's repackage script substitutes at build
// time, so this is usually a no-op there.
func Policies(browserRoot, resourceRoot string) error {
	path := filepath.Join(browserRoot, "distribution", "policies.json")
	data, err := os.ReadFile(path)
	if err != nil {
		// Missing policies.json isn't necessarily an error — some
		// builds may omit it. Skip silently.
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", path, err)
	}
	if !bytes.Contains(data, []byte(installDirPlaceholder)) {
		return nil // already self-healed
	}
	subst := toFileURIPath(resourceRoot)
	patched := bytes.ReplaceAll(data, []byte(installDirPlaceholder), []byte(subst))

	// Atomic write — never leave a half-written policies.json that
	// Firefox would refuse to parse and fail-open without policy.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, patched, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s → %s: %w", tmp, path, err)
	}
	return nil
}

// toFileURIPath converts an OS-native path into the form used after
// `file://` in a file URI. Linux/macOS just pass through. Windows
// needs backslashes flipped to forward slashes and a leading slash
// before the drive letter — so `C:\Anonymous` becomes `/C:/Anonymous`,
// producing `file:///C:/Anonymous/...` after the `file://` prefix.
func toFileURIPath(p string) string {
	if runtime.GOOS == "windows" {
		converted := strings.ReplaceAll(p, `\`, `/`)
		// Mullvad's drive letter handling: ensure a leading slash so
		// the result becomes file:///C:/... and not file://C:/...
		// (the latter is interpreted as host "C:" by some parsers).
		if !strings.HasPrefix(converted, "/") {
			converted = "/" + converted
		}
		return converted
	}
	return p
}
