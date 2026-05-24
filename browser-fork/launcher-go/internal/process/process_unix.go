//go:build !windows

package process

import (
	"os"
	"os/exec"
	"syscall"
)

// setupProcessGroup puts the child into its own process group so we
// can signal-bomb the group on shutdown without affecting the
// launcher itself or its other children.
func setupProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// terminateGroup sends SIGTERM to the child's process group (graceful).
// Falls back to the lone PID if the group lookup fails — that
// happens if the child died between Start and now.
func terminateGroup(p *os.Process) {
	if pgid, err := syscall.Getpgid(p.Pid); err == nil && pgid > 0 {
		_ = syscall.Kill(-pgid, syscall.SIGTERM)
		return
	}
	_ = p.Signal(syscall.SIGTERM)
}

// killGroup sends SIGKILL to the child's process group (hard).
func killGroup(p *os.Process) {
	if pgid, err := syscall.Getpgid(p.Pid); err == nil && pgid > 0 {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		return
	}
	_ = p.Kill()
}
