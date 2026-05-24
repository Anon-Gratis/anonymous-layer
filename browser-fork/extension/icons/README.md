# Extension icons

The 48/96/256 PNGs here come from the canonical brand source at
`browser-fork/branding/source/anonymous-logo.png` via
`browser-fork/branding/generate.sh`.

To refresh after a brand change:

```
browser-fork/branding/generate.sh
cp browser-fork/branding/generated/icon-{48,96,256}.png browser-fork/extension/icons/
browser-fork/extension/build-xpi.sh --validate
```

The legacy `generate.mjs` here (which produced a programmatic
placeholder) is kept only as a fallback for environments without
Python/PIL.
