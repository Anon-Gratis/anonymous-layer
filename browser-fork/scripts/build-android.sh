#!/usr/bin/env bash
# Build the Anon Browser fork for Android.
#
# Android Firefox lives in a DIFFERENT tree from desktop Firefox.
# Mozilla's mobile codebase is at:
#   https://github.com/mozilla-mobile/firefox-android (current)
# OR Mullvad Browser's mobile equivalent (if/when they ship one).
#
# Prerequisites:
#   - Android SDK (API 34+)
#   - Gradle
#   - JDK 17+
#   - Mozilla's mobile build environment
#   - ~60 GB free disk
#   - 16 GB RAM
#   - 30-60 minute build time
#   - Google Play developer account ($25 one-time) for Play Store distribution
#   - OR F-Droid signing key (free, no review)
#
# Output:
#   ./build/android/dist/anon-browser-VERSION-universal.apk
#
# NOTE: Mullvad Browser does NOT currently ship an Android version.
# This script targets Mozilla's Fenix-derived codebase, which would
# need its own anti-fingerprinting patches separately ported from
# Tor Browser. **THIS IS A SIGNIFICANT ADDITIONAL ENGINEERING TASK.**

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"

cat <<'NOTE'
================================================================
  ANDROID BUILD - SIGNIFICANT ADDITIONAL WORK REQUIRED
================================================================

Mullvad Browser does NOT have an Android version. To ship an Android
"Anon Browser", you need to:

  1. Fork Mozilla's Fenix (mobile Firefox) instead of Mullvad Browser
     https://github.com/mozilla-mobile/firefox-android

  2. Apply Tor Browser's mobile anti-fingerprinting patches to Fenix
     (Tor Browser DOES have an Android version; their patches are
     a starting point)

  3. Apply our branding to Fenix

  4. Bundle the anon-socks daemon (different mechanism on Android —
     usually a foreground Service in the app, or a SOCKS5 client
     library compiled in)

  5. Build, sign, distribute

This is roughly the same engineering effort as the desktop fork —
3-6 months of work — but starting from a different upstream.

For Phase 1 of this project: SKIP Android. Document that Android
users should use:
  - Orbot (a Tor SOCKS proxy app for Android) configured against
    an anon-socks daemon running somewhere
  - OR a desktop browser on a phone (slow but works)

NOTE
exit 0
