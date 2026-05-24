//go:build !cgo

package splash

import "fmt"

// newWebview is the stub used when CGO_ENABLED=0 (the cgo'd webview
// backend file is excluded by its build tag). Always returns an error
// so splash.New() falls through to the logBackend.
func newWebview() (Backend, error) {
	return nil, fmt.Errorf("webview backend not compiled in (CGo disabled)")
}
