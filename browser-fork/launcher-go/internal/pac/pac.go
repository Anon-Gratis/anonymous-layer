// Package pac renders the Tor PAC file from its template, substituting
// runtime port values. Mirrors the bash launcher's render_pac().
package pac

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// SentinelPort is the bash launcher's "1" — meaning "network type
// disabled, no real port to give." PAC content that branches on
// .onion / .i2p will skip the disabled type.
const SentinelPort = 1

// Render reads the template, substitutes @@TOR_SOCKS_PORT@@ and
// @@I2P_HTTP_PORT@@, and writes the rendered PAC to dest.
// Pass SentinelPort for any network type that's disabled.
func Render(templatePath, dest string, torSocks, i2pHTTP int) error {
	if torSocks < 0 || torSocks > 65535 {
		return fmt.Errorf("bad torSocks port: %d", torSocks)
	}
	if i2pHTTP < 0 || i2pHTTP > 65535 {
		return fmt.Errorf("bad i2pHTTP port: %d", i2pHTTP)
	}
	tpl, err := os.ReadFile(templatePath)
	if err != nil {
		return fmt.Errorf("read PAC template: %w", err)
	}
	out := strings.NewReplacer(
		"@@TOR_SOCKS_PORT@@", strconv.Itoa(torSocks),
		"@@I2P_HTTP_PORT@@", strconv.Itoa(i2pHTTP),
	).Replace(string(tpl))
	if err := os.WriteFile(dest, []byte(out), 0o644); err != nil {
		return fmt.Errorf("write PAC: %w", err)
	}
	return nil
}
