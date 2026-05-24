// Package config loads anon-browser.conf and merges env vars.
//
// The conf file format is shell-style KEY=VALUE pairs. We parse it
// strictly (no variable interpolation, no `source`, no command
// substitution) for safety — a malformed or hostile conf file should
// fail loud, never execute arbitrary code.
package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Config holds every setting the launcher reads from anon-browser.conf
// plus environment + CLI overrides. Fields map 1:1 to the bash
// launcher's variables for grep-ability.
type Config struct {
	// Bridge connection — exactly one of these blocks must apply.
	Connect string // "host:port" for direct-mode (testing)

	// Rendezvous mode.
	Consensus     string
	DATrust       string
	Descriptor    string // single descriptor .bin (optional)
	DescriptorDir string // dir of *.bin (optional, at least one of these two required)
	HSDirURL      string
	DAURLs        string // comma-separated DA endpoints for consensus refresh
	AllowColocate bool

	// Network feature toggles.
	DisableTor bool
	DisableI2P bool // default true; we skip i2pd in MVP

	// Bridge bind / port (env-overridable).
	BridgeHost string
	BridgePort int

	// Install layout — derived from launcher binary location, not
	// from the conf. Mirrors $ANON_DIR / $ROOT / etc. in bash.
	InstallDir   string // e.g. ~/anon-browser on Linux, C:\Anonymous on Windows
	AnonDir      string // $InstallDir/AnonLayer
	BrowserRoot  string // $InstallDir/Browser
	// ResourceRoot is the dir whose path needs to fill @@INSTALL_DIR@@
	// in policies.json's file:// URIs. On Linux/Windows that's
	// InstallDir; on macOS it's Contents/Resources within the .app
	// bundle (since the launcher lives at Contents/MacOS but the
	// browser tree + AnonLayer live one dir up under Resources).
	ResourceRoot string
}

// Load reads conf from the canonical path (derived from installDir),
// applies env-var overrides, and validates required fields. Returns
// the populated config or an error if the conf is malformed / missing
// required fields.
func Load(installDir string) (*Config, error) {
	// macOS .app bundle layout: the launcher binary lives at
	// `Anonymous.app/Contents/MacOS/anonymous`, but the browser tree
	// and AnonLayer/ live one dir up under `Contents/Resources/`.
	// installDir (the dir containing the launcher) maps to MacOS/, so
	// we resolve the sibling Resources/ dir for everything else.
	anonDir := filepath.Join(installDir, "AnonLayer")
	browserRoot := filepath.Join(installDir, "Browser")
	resourceRoot := installDir
	if runtime.GOOS == "darwin" {
		resources := filepath.Join(installDir, "..", "Resources")
		// Only switch if the Resources dir actually exists — keeps
		// behavior sane for dev/test layouts that aren't .app bundles.
		if st, err := os.Stat(resources); err == nil && st.IsDir() {
			anonDir = filepath.Join(resources, "AnonLayer")
			browserRoot = filepath.Join(resources, "Browser")
			resourceRoot = resources
		}
	}

	c := &Config{
		InstallDir:   installDir,
		AnonDir:      anonDir,
		BrowserRoot:  browserRoot,
		ResourceRoot: resourceRoot,
		// Bash defaults (anon-browser.launcher.sh lines 25–26).
		BridgeHost: envOr("ANON_BRIDGE_HOST", "127.0.0.1"),
		BridgePort: envIntOr("ANON_BRIDGE_PORT", 1081),
		// Default i2pd off (matches bash default ANON_DISABLE_I2P=1).
		DisableI2P: true,
	}

	confPath := filepath.Join(c.AnonDir, "config", "anon-browser.conf")
	f, err := os.Open(confPath)
	if err != nil {
		return nil, fmt.Errorf("open conf %s: %w", confPath, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("%s:%d: malformed line %q", confPath, lineNo, line)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		// Strip optional surrounding quotes — bash-style "foo" or 'foo'.
		val = unquote(val)
		switch key {
		case "CONNECT":
			c.Connect = val
		case "CONSENSUS":
			c.Consensus = val
		case "DA_TRUST":
			c.DATrust = val
		case "DESCRIPTOR":
			c.Descriptor = val
		case "DESCRIPTOR_DIR":
			c.DescriptorDir = val
		case "HSDIR_URL":
			c.HSDirURL = val
		case "DA_URLS":
			c.DAURLs = val
		case "ALLOW_CO_LOCATED":
			c.AllowColocate = val == "1" || strings.EqualFold(val, "true")
		case "ANON_DISABLE_TOR":
			c.DisableTor = val == "1" || strings.EqualFold(val, "true")
		case "ANON_DISABLE_I2P":
			c.DisableI2P = val == "1" || strings.EqualFold(val, "true")
		default:
			// Unknown keys are ignored — forward-compat with future
			// conf options. The bash version does the same (any
			// sourced var that no function reads is harmless).
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read conf: %w", err)
	}

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// validate mirrors the bash launcher's mode dispatch at lines 479–521:
// either CONNECT is set, OR (CONSENSUS + DA_TRUST + (DESCRIPTOR OR
// DESCRIPTOR_DIR)).
func (c *Config) validate() error {
	if c.Connect != "" {
		return nil
	}
	if c.Consensus == "" || c.DATrust == "" {
		return fmt.Errorf("rendezvous mode requires CONSENSUS and DA_TRUST (or set CONNECT)")
	}
	if c.Descriptor == "" && c.DescriptorDir == "" && c.HSDirURL == "" {
		return fmt.Errorf("rendezvous mode requires at least one descriptor source " +
			"(DESCRIPTOR, DESCRIPTOR_DIR, or HSDIR_URL)")
	}
	return nil
}

// IsConnectMode reports whether the bridge should use --connect.
func (c *Config) IsConnectMode() bool { return c.Connect != "" }

// envOr returns the env value of key, or fallback if unset.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envIntOr returns the env value of key parsed as int, or fallback.
func envIntOr(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// unquote strips one layer of matching single or double quotes.
func unquote(s string) string {
	if len(s) < 2 {
		return s
	}
	if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}
