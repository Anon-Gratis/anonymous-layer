# Build scripts

These scripts are skeleton automation for forking and building
Mullvad Browser with our patches + branding. **They document the
path; they do not produce binaries on their own.** You execute them
with the right toolchains installed.

## Prerequisites by platform

### All platforms

- Git
- Network access for the source fetch (~30 GB)
- ~100 GB disk space per build (depending on platform)

### Linux

- Ubuntu 22.04 LTS or Debian 12 (clean VM recommended)
- See https://firefox-source-docs.mozilla.org/setup/linux_build.html
- `apt install build-essential libgtk-3-dev libdbus-glib-1-dev …`

### macOS

- macOS hardware (Apple Silicon or Intel)
- Xcode + Command Line Tools
- `brew install autoconf@2.13 yasm` (and others)
- An Apple Developer Program membership ($99/year) for signing

### Windows

- Windows 11
- Visual Studio 2022 with C++ workload
- Windows SDK
- An EV code signing certificate ($300-500/year) for SmartScreen pass

### Android

- Android Studio + SDK (API level 34+)
- Gradle
- Google Play developer account ($25 one-time) OR F-Droid signing

## Pipeline

```
fetch-source.sh        → ./mullvad-browser/ (Mullvad source)
                            │
apply-patches.sh       → ./mullvad-browser/ (patched with our branding + bundled daemon)
                            │
build-<platform>.sh    → ./build/<platform>/  (build artifacts)
                            │
sign-<platform>.sh     → signed artifacts
                            │
package-<platform>.sh  → .deb, .dmg, .exe, .apk
```

The `sign-*` and `package-*` scripts are not yet provided —
their content depends on which signing service / packaging
infrastructure you choose. Document them as part of your operational
runbook.

## CI

The `.github/workflows/build-and-release.yml` file in this directory
defines a GitHub Actions matrix that, given:

- Repository secrets for signing keys
- macOS / Windows runners
- Appropriate trigger events (tag pushes, manual dispatch)

will run the equivalent of these scripts in CI. **Secrets you need
to configure**:

| Secret | Used for | Source |
|---|---|---|
| `APPLE_CERT_P12` | macOS signing | Apple Developer portal |
| `APPLE_CERT_PASSWORD` | macOS signing | You set this |
| `APPLE_NOTARIZE_USER` | macOS notarize | Apple ID with Developer program |
| `APPLE_NOTARIZE_PASSWORD` | macOS notarize | App-specific password |
| `WINDOWS_CERT_PFX` | Windows signing | DigiCert/Sectigo/etc EV cert |
| `WINDOWS_CERT_PASSWORD` | Windows signing | You set this |
| `ANDROID_KEYSTORE` | Android signing | Generated once via keytool |
| `ANDROID_KEYSTORE_PASSWORD` | Android signing | You set this |
| `ANDROID_KEY_ALIAS` | Android signing | Set when generating keystore |

Without these secrets, the workflows will run but produce
unsigned/untrusted artefacts. Users see scary warnings on download.

## Maintenance

After every Mullvad Browser release (typically 1-2 weeks after each
Firefox release):

1. Pull the new tag in `fetch-source.sh`
2. Re-run `apply-patches.sh` (may need conflict resolution if
   Mullvad / Firefox changed files we patch)
3. Re-build all 4 platforms
4. Re-sign / re-notarize
5. Upload to your distribution channels
6. Push to auto-update server

This cycle is on the order of 1-3 days of engineering time **if
nothing has broken upstream**. Plan for 30-50% slack for
unexpected issues.
