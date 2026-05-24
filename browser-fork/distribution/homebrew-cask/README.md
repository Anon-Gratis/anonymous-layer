# Homebrew Cask distribution

This directory holds the Homebrew Cask formula for Anonymous Browser.
Homebrew Cask is the de-facto macOS package manager for unsigned
binaries — it **strips the `com.apple.quarantine` attribute** during
install, which means users never see the dreaded "Anonymous can't be
opened because the developer cannot be verified" Gatekeeper dialog.

## End-user install flow

```bash
# Once per user: add the tap
brew tap anon-gratis/anonymous

# Install / upgrade
brew install --cask anonymous-browser
brew upgrade  --cask anonymous-browser
```

That's the entire flow. No password, no `xattr` voodoo, no right-click → Open.

## Tap layout

The public tap repo (`anon-gratis/homebrew-anonymous`) only
needs:

```
Casks/
└── anonymous-browser.rb    ← this formula, exact copy
```

(Homebrew naming convention: a tap repo MUST be named
`homebrew-<short-name>` so `brew tap user/short-name` works; the
files live under `Casks/`.)

## Release checklist

For each release tag pushed to `anon-gratis/anonymous-layer`:

1. CI (Task #24, `release.yml`) builds the macOS .dmg for both
   arm64 and amd64 on `macos-latest` + `macos-13` runners, and
   uploads them as `anonymous-<VER>-macos-{arm64,x86_64}.dmg` to the
   GitHub release.
2. Bump `version` in this formula to match the tag (without the `v`
   prefix).
3. Replace the two `sha256` placeholders with the values from
   `dist/anonymous-<VER>-macos-{arm64,x86_64}.dmg.sha256`.
4. Copy `anonymous-browser.rb` from here into the tap repo's `Casks/`
   directory, commit, push. `brew install --cask anonymous-browser`
   from the tap then resolves the new release.

`livecheck` is set to `strategy: :github_latest` so `brew livecheck
anonymous-browser` will tell you when a new GitHub release exists that
the formula hasn't caught up to.

## Why a tap (vs. homebrew/cask)?

- `homebrew/cask` requires the cask to meet activity heuristics (stars,
  forks, age) and has a multi-week PR review queue. Tap repos are
  instant.
- We're a pre-audit testnet project — submitting to the main
  homebrew/cask repo before the audit closes would be premature.
- Migration is a metadata-only change: when ready, we open a PR with
  this exact `.rb` and the formula's URL/SHA stays the same.

## Why a Cask, not a Formula?

Formulas (`brew install foo`) are for source builds + CLI tools that
go into `/opt/homebrew/bin/`. Casks (`brew install --cask foo`) are
for pre-built GUI apps that go into `/Applications/`. Anonymous is the
latter.
