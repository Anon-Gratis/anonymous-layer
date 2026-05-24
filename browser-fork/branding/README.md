# Branding assets

This directory holds the brand-override files needed to rename
Mullvad Browser → "Anon Browser" in a fork.

**Nothing here is real artwork.** You need to commission or design
the actual logos, icons, and visual identity. These files are
placeholders showing the structure.

## What you need to produce

| Asset | Format | Sizes | Notes |
|---|---|---|---|
| App icon | PNG | 16, 32, 48, 64, 128, 256, 512 px | Square. For the .ico/.icns/.iconset bundle. |
| App icon | SVG | vector | Source for re-export. |
| About-page logo | PNG | 192×96 (and 2× for Retina) | Shown at `about:` page top. |
| Splash logo | PNG | 512×512 (and 2× for Retina) | Optional; only some platforms use it. |
| Tab-bar logo | SVG | 16×16 effective | Shown on the new-tab button or near the URL bar. |
| Installer wallpaper | PNG | 600×400 | Windows installer / macOS .dmg backdrop. |
| Brand color palette | hex codes | — | Primary / accent / chrome-tinted accent. |

## Strings to update

In addition to artwork, the fork needs to rename text strings
throughout the browser UI. The main strings live in:

- `browser/branding/anon/locales/en-US/brand.properties` (Mullvad
  has equivalent at `browser/branding/mb/locales/en-US/`)
- `browser/branding/anon/locales/en-US/brand.dtd`
- `browser/branding/anon/locales/en-US/brand.ftl` (Fluent strings —
  newer Firefox uses these)

The `strings.dtd` skeleton in this directory shows the structure.

## How the fork wires it up

In `browser/branding/anon/configure.sh` (created during the fork):

```bash
MOZ_APP_DISPLAYNAME="Anon Browser"
MOZ_APP_REMOTINGNAME="anon-browser"
MOZ_APP_BASENAME="AnonBrowser"
MOZ_APP_VENDOR="Anonymous Layer"
MOZ_DISTRIBUTION_ID="org.anon-layer.browser"
MOZ_MACBUNDLE_ID="org.anon-layer.browser"
```

And patches to:

- `browser/app/macbuild/Info.plist.in` → MOZ_MACBUNDLE_ID
- `browser/app/Makefile.in` → branding directory selection
- `browser/installer/windows/nsis/installer.nsi` → installer
  references
- `mobile/android/branding/anon/` → Android (separate tree)

These wirings are documented in
[Mozilla's branding docs](https://firefox-source-docs.mozilla.org/setup/configuring_build_options.html#branding)
and adapted by Mullvad in `browser/branding/mb/`.

## License of artwork

If you commission artwork, **make sure the contract gives YOU the
copyright** OR licenses it under an OSI-approved license compatible
with AGPL-3.0+ (the project license). Otherwise you can't ship the
fork.

## Placeholder identification

For now, until real artwork exists, use:

- App icon: a plain monochrome glyph (e.g., a stylized A or a
  network-graph icon) — anyone can knock out a 1-hour mockup
- Color palette: black background, single accent color
- Strings: literal "Anon Browser" with no marketing copy

Real artwork is a small investment ($500-2000 for a logo + icon
suite from a freelance designer) but worth doing professionally if
you're going to ship branded binaries.
