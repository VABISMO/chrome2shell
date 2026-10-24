#!/usr/bin/env python3
"""Descarga una build concreta de Chrome for Testing (Linux x64).

Chrome for Testing publica builds historicas en:
    https://storage.googleapis.com/chrome-for-testing-public/<version>/linux64/chrome-linux64.zip

Eso permite fijar la version exacta afectada por un CVE y comparar contra la
primera version parcheada. El binario se guarda en builds/<version>/.

Uso:
    python3 scripts/fetch_chrome.py 155.0.8059.84 156.0.8078.47
    python3 scripts/fetch_chrome.py 155.0.8059.79 --force
"""
from __future__ import annotations

import argparse
import shutil
import stat
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = "https://storage.googleapis.com/chrome-for-testing-public"
PLATFORM = "linux64"
ASSET = "chrome-linux64.zip"


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def download(version: str, dest: Path, force: bool) -> Path:
    binary = dest / "chrome-linux64" / "chrome"
    if binary.exists() and not force:
        print(f"[=] {version} ya presente en {binary}")
        return binary

    url = f"{BASE}/{version}/{PLATFORM}/{ASSET}"
    dest.mkdir(parents=True, exist_ok=True)
    zip_path = dest / ASSET
    print(f"[+] {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "chrome-cve-lab/0.1"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(zip_path, "wb") as fh:
        total = int(resp.headers.get("Content-Length") or 0)
        done = 0
        while chunk := resp.read(1 << 20):
            fh.write(chunk)
            done += len(chunk)
            if total:
                pct = done * 100 / total
                sys.stdout.write(f"\r    {human(done)} / {human(total)} ({pct:5.1f}%)")
                sys.stdout.flush()
    print()

    with zipfile.ZipFile(zip_path) as zf:
        bad = zf.testzip()
        if bad:
            raise RuntimeError(f"zip corrupto: {bad}")
        zf.extractall(dest)
    zip_path.unlink()

    binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"[+] listo: {binary}")
    return binary


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("versions", nargs="+")
    ap.add_argument("--dest", default=str(ROOT / "builds"))
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    for version in args.versions:
        target = Path(args.dest) / version
        try:
            download(version, target, args.force)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] {version}: {exc}", file=sys.stderr)
            shutil.rmtree(target, ignore_errors=True)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
