#!/usr/bin/env python3
# refresh-browser-page.py — patch browser.html with the current release's
# version, per-platform filenames, sha256 checksums, and file sizes.
#
# Two source modes:
#   --source local   (default)
#     Read dist/*.sha256 next to this repo's root. Useful after running
#     the repackage scripts locally.
#
#   --source github --tag v0.0.1-pre
#     Fetch asset list + checksums from
#       github.com/anon-gratis/anonymous-layer/releases/tag/<tag>
#     Useful after release.yml has uploaded a tag's artifacts.
#
# Usage:
#   browser-fork/distribution/website/refresh-browser-page.py
#   browser-fork/distribution/website/refresh-browser-page.py --version 0.0.1-pre
#   browser-fork/distribution/website/refresh-browser-page.py --source github --tag v0.0.1-pre
#   browser-fork/distribution/website/refresh-browser-page.py --dry-run

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import urllib.request

# ---------- platform classifier ----------
#
# Each download card / checksum row in browser.html is keyed on one of
# these short labels. The classifier maps a release filename to its
# label or returns None if the file isn't a download artifact.

PLATFORMS = {
    "linux":       re.compile(r"^anonymous-(?P<v>[\w.-]+)-linux-x86_64\.tar\.xz$"),
    "windows":     re.compile(r"^anonymous-(?P<v>[\w.-]+)-windows-x86_64\.zip$"),
    "macos_arm":   re.compile(r"^anonymous-(?P<v>[\w.-]+)-macos-arm64\.dmg$"),
    "macos_intel": re.compile(r"^anonymous-(?P<v>[\w.-]+)-macos-x86_64\.dmg$"),
}


def classify(filename: str) -> tuple[str | None, str | None]:
    """Return (platform_key, version) or (None, None)."""
    for key, pat in PLATFORMS.items():
        m = pat.match(filename)
        if m:
            return key, m.group("v")
    return None, None


# ---------- sources ----------

def collect_local(dist_dir: pathlib.Path) -> dict[str, dict]:
    """Scan dist/ for *.sha256 sidecars; return {platform: {file,sha,size}}."""
    if not dist_dir.is_dir():
        sys.exit(f"refresh: no dist dir at {dist_dir}")
    out: dict[str, dict] = {}
    for sha_path in sorted(dist_dir.glob("anonymous-*.sha256")):
        artifact_name = sha_path.stem  # strips trailing .sha256
        key, ver = classify(artifact_name)
        if key is None:
            continue
        # .sha256 file content: "<hex>  <filename>"
        line = sha_path.read_text().strip().split()
        if not line:
            continue
        sha = line[0]
        artifact = dist_dir / artifact_name
        size = artifact.stat().st_size if artifact.is_file() else None
        out[key] = {"file": artifact_name, "sha": sha, "size": size, "version": ver}
    return out


def collect_github(tag: str, repo: str = "anon-gratis/anonymous-layer") -> dict[str, dict]:
    """Fetch release assets from GitHub. Each .sha256 sidecar is read inline."""
    url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
    req = urllib.request.Request(url, headers={"User-Agent": "refresh-browser-page/1"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            release = json.load(resp)
    except Exception as e:
        sys.exit(f"refresh: GitHub API failed: {e}")

    assets = {a["name"]: a for a in release.get("assets", [])}
    out: dict[str, dict] = {}
    for name, asset in assets.items():
        key, ver = classify(name)
        if key is None:
            continue
        # Find the matching .sha256 sidecar and read it inline.
        sha_name = name + ".sha256"
        sha = ""
        if sha_name in assets:
            try:
                sha_url = assets[sha_name]["browser_download_url"]
                sha = urllib.request.urlopen(sha_url, timeout=10).read().decode().split()[0]
            except Exception:
                sha = ""
        out[key] = {
            "file": name,
            "sha": sha,
            "size": asset.get("size"),
            "version": ver,
        }
    return out


# ---------- HTML patcher ----------
#
# Each patch is anchored on enough surrounding HTML to make it
# unambiguous, then replaces only the value. Idempotent: re-running
# with the same artifacts produces no diff.

def human_size(n: int | None) -> str:
    if n is None:
        return "—"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024
    return f"{n:.0f} TB"


def patch(html: str, art: dict[str, dict], version: str) -> str:
    # --- 1. tagline version (header.brand .tagline) ---
    html = re.sub(
        r'(<span class="tagline">pre-audit testnet · v)[\w.-]+(</span>)',
        rf'\g<1>{version}\g<2>',
        html,
    )

    # --- 2. per-platform: filename in download .btn href ---
    for key, sel_regex in (
        ("linux",       r"anonymous-[\w.-]+-linux-x86_64\.tar\.xz"),
        ("windows",     r"anonymous-[\w.-]+-windows-x86_64\.zip"),
        ("macos_arm",   r"anonymous-[\w.-]+-macos-arm64\.dmg"),
        ("macos_intel", r"anonymous-[\w.-]+-macos-x86_64\.dmg"),
    ):
        if key not in art:
            continue
        new = art[key]["file"]
        # Replace the filename in URLs (preserves .sha256 sidecar URLs too).
        html = re.sub(sel_regex, new, html)

    # --- 3. file sizes in .dl .arch lines (e.g. ".tar.xz · 137 MB") ---
    for key, label_regex in (
        ("linux",   r"(\.tar\.xz · )\d+ [KMG]?B"),
        ("windows", r"(\.zip · )\d+ [KMG]?B"),
        # macOS: .dmg arch line has no size shown in the draft (it's a
        # placeholder until first build), so we skip on missing
        # arm/intel artifacts. If both are present, show arm's size.
    ):
        if key in art:
            sz = human_size(art[key]["size"])
            html = re.sub(label_regex, rf"\g<1>{sz}", html)

    # --- 4. checksum block: per-platform hash ---
    # The block looks like:
    #   <span class="file">anonymous-<...>-linux-x86_64.tar.xz</span>  <SHA>
    # We anchor on the class+filename, replace whatever follows the
    # closing </span> up to the end of the line.
    # Each checksum row is a single <div>...</div> on one line. Match the
    # whole row from <span class="file">…</span> up to </div>, lazy, so
    # we swallow whatever previous value (hex hash OR <em>placeholder</em>)
    # is sitting between them and overwrite it cleanly. Avoids the
    # double-<em> bug where a positive lookahead on `<` left the old
    # tag in place.
    for key, file_regex in (
        ("linux",       r"anonymous-[\w.-]+-linux-x86_64\.tar\.xz"),
        ("windows",     r"anonymous-[\w.-]+-windows-x86_64\.zip"),
        ("macos_arm",   r"anonymous-[\w.-]+-macos-arm64\.dmg"),
        ("macos_intel", r"anonymous-[\w.-]+-macos-x86_64\.dmg"),
    ):
        anchor = rf'(<span class="file">{file_regex}</span>)[^\n]*?(</div>)'
        if key in art:
            new = art[key]["sha"]
        else:
            new = '<em style="color:var(--muted)">building soon</em>'
        html = re.sub(anchor, rf'\1  {new}\2', html)

    # --- 5. macOS card: toggle .coming-soon class based on artifact presence ---
    has_mac = "macos_arm" in art or "macos_intel" in art
    if has_mac:
        # Remove the coming-soon class + flip the placeholder button.
        html = html.replace(
            '<div class="dl coming-soon">',
            '<div class="dl">',
        )
        # Pick first available mac artifact for the primary button.
        primary = art.get("macos_arm") or art["macos_intel"]
        html = re.sub(
            r'<a class="btn" href="#">Coming soon</a>',
            f'<a class="btn" href="https://github.com/anon-gratis/anonymous-layer/releases/latest/download/{primary["file"]}" rel="noopener">Download .dmg</a>',
            html,
        )
        # Drop the "status" line if present.
        html = re.sub(
            r'\s*<div class="status">building soon</div>',
            '',
            html,
        )
    else:
        # No Mac artifact — make sure the page still shows coming-soon.
        # Idempotent: if already set, no-op.
        if '<div class="dl">\n    <span class="bracket tl"></span>\n    <span class="bracket br"></span>\n    <h3>macOS</h3>' in html:
            html = html.replace(
                '<div class="dl">\n    <span class="bracket tl"></span>\n    <span class="bracket br"></span>\n    <h3>macOS</h3>',
                '<div class="dl coming-soon">\n    <span class="bracket tl"></span>\n    <span class="bracket br"></span>\n    <h3>macOS</h3>',
            )

    return html


# ---------- main ----------

def main() -> int:
    p = argparse.ArgumentParser(description="Patch browser.html with current release artifacts.")
    p.add_argument("--source", choices=("local", "github"), default="local")
    p.add_argument("--tag", help="GitHub release tag (e.g. v0.0.1-pre). Required for --source github.")
    p.add_argument("--repo", default="anon-gratis/anonymous-layer",
                   help="GitHub owner/repo for --source github.")
    p.add_argument("--version", help="Override version string in the page tagline. "
                                     "If unset, taken from the artifact filenames.")
    p.add_argument("--dist", help="Path to dist/ for --source local. Defaults to <repo>/dist/.")
    p.add_argument("--page", help="Path to browser.html. Defaults to alongside this script.")
    p.add_argument("--dry-run", action="store_true", help="Show diff, don't write.")
    args = p.parse_args()

    here = pathlib.Path(__file__).resolve().parent
    page_path = pathlib.Path(args.page) if args.page else here / "browser.html"
    if not page_path.is_file():
        sys.exit(f"refresh: no page at {page_path}")

    # Discover release artifacts.
    if args.source == "local":
        dist = pathlib.Path(args.dist) if args.dist else here.parents[2] / "dist"
        art = collect_local(dist)
    else:
        if not args.tag:
            sys.exit("refresh: --tag is required with --source github")
        art = collect_github(args.tag, args.repo)

    if not art:
        sys.exit("refresh: no release artifacts found")

    # Version: explicit override > common version across artifacts > error.
    if args.version:
        version = args.version
    else:
        versions = {a["version"] for a in art.values() if a.get("version")}
        if len(versions) != 1:
            sys.exit(f"refresh: ambiguous version across artifacts: {versions}; pass --version")
        version = versions.pop()

    # Patch.
    original = page_path.read_text(encoding="utf-8")
    patched = patch(original, art, version)

    if patched == original:
        print(f"refresh: {page_path.name} already up to date")
        return 0

    if args.dry_run:
        import difflib
        for line in difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=str(page_path) + " (current)",
            tofile=str(page_path) + " (proposed)",
            n=1,
        ):
            sys.stdout.write(line)
        return 0

    page_path.write_text(patched, encoding="utf-8")
    print(f"refresh: patched {page_path}")
    for key, a in sorted(art.items()):
        print(f"  {key:12s} → {a['file']} ({human_size(a.get('size'))})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
