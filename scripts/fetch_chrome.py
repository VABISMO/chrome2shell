#!/usr/bin/env python3
"""Download an exact Chrome for Testing build (Linux x64).

Chrome for Testing publishes historical builds at:
    https://storage.googleapis.com/chrome-for-testing-public/<version>/linux64/chrome-linux64.zip

That makes it possible to pin the exact version affected by a CVE and compare
it against the first patched one. The binary is stored in builds/<version>/.

Usage:
    python3 scripts/fetch_chrome.py 155.0.8059.84 156.0.8078.47
    python3 scripts/fetch_chrome.py 152.0.7977.75 152.0.7977.82 --connections 16
    python3 scripts/fetch_chrome.py 155.0.8059.79 --force

`--connections N` downloads the zip as N parallel byte ranges (the server
supports Range; each connection is throttled independently, so aggregate
throughput scales with N). Falls back to the single stream automatically if
the server ever ignores Range. The zip is verified with zipfile.testzip()
either way.
"""
from __future__ import annotations

import argparse
import shutil
import stat
import sys
import threading
import time
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = "https://storage.googleapis.com/chrome-for-testing-public"
PLATFORM = "linux64"
ASSET = "chrome-linux64.zip"
UA = "chrome-cve-lab/0.1"


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def fetch_sequential(url: str, zip_path: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
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


def fetch_parallel(url: str, zip_path: Path, connections: int) -> None:
    """Download as N byte ranges written at their offsets (disjoint writes)."""
    head = urllib.request.Request(url, method="HEAD", headers={"User-Agent": UA})
    with urllib.request.urlopen(head, timeout=60) as resp:
        size = int(resp.headers.get("Content-Length") or 0)
    if size <= 0:
        raise RuntimeError("no Content-Length, cannot range")

    chunk = (size + connections - 1) // connections
    ranges = [(s, min(s + chunk, size) - 1) for s in range(0, size, chunk)]
    lock = threading.Lock()
    state = {"done": 0, "ignored_range": False}

    with open(zip_path, "wb") as fh:
        fh.truncate(size)  # preallocate so each worker writes at its own offset

    def worker(start: int, end: int) -> None:
        if state["ignored_range"]:
            return
        last_err: Exception | None = None
        for attempt in range(4):
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": UA, "Range": f"bytes={start}-{end}"}
                )
                with urllib.request.urlopen(req, timeout=180) as resp:
                    if resp.status != 206:
                        state["ignored_range"] = True
                        raise RuntimeError("server ignored Range")
                    with open(zip_path, "r+b") as fh:
                        fh.seek(start)
                        got = start
                        while data := resp.read(1 << 16):
                            fh.write(data)
                            got += len(data)
                            with lock:
                                state["done"] += len(data)
                                pct = state["done"] * 100 / size
                                sys.stdout.write(
                                    f"\r    {human(state['done'])} / {human(size)} "
                                    f"({pct:5.1f}%) {connections} conns"
                                )
                                sys.stdout.flush()
                    if got != end + 1:
                        raise RuntimeError(f"short range {start}-{end}: got {got}")
                return
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                if state["ignored_range"]:
                    raise
                time.sleep(1 + attempt)
        raise RuntimeError(f"range {start}-{end}: {last_err}")

    with ThreadPoolExecutor(max_workers=connections) as ex:
        for fut in [ex.submit(worker, s, e) for s, e in ranges]:
            fut.result()
    print()
    if state["ignored_range"]:
        raise RuntimeError("server ignored Range")


def download(version: str, dest: Path, force: bool, connections: int = 1) -> Path:
    binary = dest / "chrome-linux64" / "chrome"
    if binary.exists() and not force:
        print(f"[=] {version} already present at {binary}")
        return binary

    url = f"{BASE}/{version}/{PLATFORM}/{ASSET}"
    dest.mkdir(parents=True, exist_ok=True)
    zip_path = dest / ASSET
    print(f"[+] {url}")
    if connections > 1:
        try:
            fetch_parallel(url, zip_path, connections)
        except Exception as exc:  # noqa: BLE001
            print(f"\n[!] parallel fetch failed ({exc}); single stream", file=sys.stderr)
            zip_path.unlink(missing_ok=True)
            fetch_sequential(url, zip_path)
    else:
        fetch_sequential(url, zip_path)

    with zipfile.ZipFile(zip_path) as zf:
        bad = zf.testzip()
        if bad:
            raise RuntimeError(f"corrupt zip: {bad}")
        # extractall() does not restore unix permissions: without this,
        # chrome_crashpad_handler fails and startup aborts with SIGABRT.
        for info in zf.infolist():
            target = Path(zf.extract(info, dest))
            mode = (info.external_attr >> 16) & 0o777
            if mode:
                target.chmod(mode)
    zip_path.unlink()

    binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"[+] ready: {binary}")
    return binary


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("versions", nargs="+")
    ap.add_argument("--dest", default=str(ROOT / "builds"))
    ap.add_argument("--force", action="store_true")
    ap.add_argument(
        "--connections",
        type=int,
        default=1,
        help="parallel byte-range connections per zip (default 1 = single stream)",
    )
    args = ap.parse_args()

    for version in args.versions:
        target = Path(args.dest) / version
        try:
            download(version, target, args.force, args.connections)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] {version}: {exc}", file=sys.stderr)
            shutil.rmtree(target, ignore_errors=True)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
