# Homebrew Cask formula for Anonymous Browser.
#
# Lives in this repo as the source of truth; mirror to the public tap
# (anon-gratis/homebrew-anonymous) on each release. Users install
# via:
#   brew tap anon-gratis/anonymous
#   brew install --cask anonymous-browser
#
# Why a tap (not homebrew/cask) for v1: homebrew/cask requires a
# minimum number of stars / activity heuristics and the security
# review takes weeks. A self-hosted tap ships now and migrating to
# homebrew/cask later is a metadata-only change.
#
# Homebrew automatically strips the com.apple.quarantine attribute on
# any cask binary, which is the entire reason we route through brew
# instead of asking users to wrestle with Gatekeeper.

cask "anonymous-browser" do
  version "0.0.0-pre"
  sha256 arm:   "0000000000000000000000000000000000000000000000000000000000000000",
         intel: "0000000000000000000000000000000000000000000000000000000000000000"

  url "https://github.com/anon-gratis/anonymous-layer/releases/download/v#{version}/anonymous-#{version}-macos-#{Hardware::CPU.arm? ? "arm64" : "x86_64"}.dmg",
      verified: "github.com/anon-gratis/anonymous-layer/"

  name "Anonymous Browser"
  desc "Anonymity-focused web browser for the Tor and anon-layer networks"
  homepage "https://anonymous.gratis"

  livecheck do
    url :url
    strategy :github_latest
  end

  auto_updates false
  depends_on macos: ">= :big_sur"

  app "Anonymous.app"

  # Anything the user has personalized — config edits, descriptor cache,
  # profile state — survives `brew upgrade --cask anonymous-browser`.
  zap trash: [
    "~/Library/Application Support/Anonymous",
    "~/Library/Caches/Anonymous",
    "~/Library/Preferences/gratis.anonymous.browser.plist",
    "~/Library/Saved Application State/gratis.anonymous.browser.savedState",
  ]

  caveats <<~EOS
    Anonymous Browser is a PRE-AUDIT TESTNET build of the anon-layer
    protocol. Do not rely on it for life-critical anonymity.

    First-time setup:
      1. Open Anonymous.app once (Cmd+Space → "Anonymous").
      2. The launcher creates ~/Library/Application Support/Anonymous/
         and seeds a default config.
      3. Edit DA_URLS / HSDIR_URL in that folder if you're not using
         the default pre-audit testnet directory authorities.

    Threat model + project status:
      https://github.com/anon-gratis/anonymous-layer

    i2pd is NOT bundled in the macOS build (no upstream Mac release
    from PurpleI2P). If you need .i2p access:
      brew install i2pd
      # then point AnonLayer's i2pd.conf at /opt/homebrew/bin/i2pd
  EOS
end
