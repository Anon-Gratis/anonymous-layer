# Scoop distribution

This directory holds the Scoop manifest for Anonymous Browser. Scoop
([scoop.sh](https://scoop.sh/)) is the de-facto package manager for
"portable Windows apps installed without admin." Users opt into our
trust model by adding our bucket, then `scoop install` does the
download + extract + Start Menu shortcut + PATH wiring with no
SmartScreen prompts (because Scoop itself fetches the .zip, not the
user via their browser, so Mark-of-the-Web never triggers).

## End-user install flow

```powershell
# Once per machine: install Scoop if not present
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
iwr -useb get.scoop.sh | iex

# Once per user: add our bucket
scoop bucket add anonymous-gratis https://github.com/anon-gratis/scoop-anonymous

# Install / update Anonymous Browser
scoop install anonymous-browser
scoop update  anonymous-browser
```

## Bucket layout

The public bucket repo (`anon-gratis/scoop-anonymous`) only needs:

```
bucket/
└── anonymous-browser.json    ← this manifest, exact copy
```

Scoop's `checkver` + `autoupdate` blocks in the manifest mean the bucket
self-updates: a maintainer just runs `scoop checkver -u anonymous-browser`
after each release and commits the result.

## Release checklist

For each release tag pushed to `anon-gratis/anonymous-layer`:

1. CI (Task #24) builds `anonymous-<VER>-windows-x86_64.zip` and uploads
   it + its `.sha256` to the GitHub release.
2. Bump `version` in this manifest to match the tag (without the `v`
   prefix).
3. Run `scoop checkver -u anonymous-browser` against this manifest —
   it fetches the new URL, computes the sha256, and rewrites the
   `hash` field.
4. Copy `anonymous-browser.json` from here into the public bucket repo,
   commit, push.

## Why Scoop, not Chocolatey/Winget?

- **Scoop**: no admin, no MSI, no SmartScreen. Single-user portable
  installs. Perfect for our threat model (no need to elevate, no
  global system changes).
- **Chocolatey**: requires admin; users would see a UAC prompt and
  potentially a SmartScreen prompt during the .ps1 install script.
- **Winget**: requires the manifest to be signed by a verified
  publisher to skip prompts; functionally we'd need the same Microsoft
  Trusted Signing cert as the standalone .exe distribution. Defer
  until we have the cert.

We may add Winget later as a secondary path; Scoop is the launch path.
