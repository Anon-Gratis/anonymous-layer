//go:build windows

package process

import (
	"os"
	"os/exec"
)

// setupProcessGroup is a no-op on Windows for the MVP. A future phase
// can set syscall.SysProcAttr{CreationFlags: CREATE_NEW_PROCESS_GROUP}
// so Ctrl+Break can be sent to the group via GenerateConsoleCtrlEvent.
// For now, each child runs in the launcher's group; clean shutdown
// uses os.Process.Kill which translates to TerminateProcess.
func setupProcessGroup(cmd *exec.Cmd) {
	// intentionally blank
}

// terminateGroup on Windows: try a graceful interrupt first. Windows
// doesn't have POSIX signal semantics, so os.Interrupt is approximate
// (delivered as CTRL_C_EVENT in console contexts; not delivered at
// all for windowed processes). Hard kill follows in Stop() after the
// grace period either way.
func terminateGroup(p *os.Process) {
	_ = p.Signal(os.Interrupt)
}

// killGroup on Windows: TerminateProcess via os.Process.Kill.
func killGroup(p *os.Process) {
	_ = p.Kill()
}
