#!/usr/bin/env python3
"""Build data/cves.json from the official Chrome Releases feed.

Source: https://chromereleases.googleblog.com/feeds/posts/default/-/Stable%20updates

For every stable release the blog publishes lines in the form:

    [N/A][ 568719351 ] Critical CVE-2026-110922: Use after free in Prerender.

From there we extract severity, component, CVE and -- most importantly -- the
crbug.com bug ID, which is public and lets us locate the fix commit.

Usage:
    python3 scripts/sync_cves.py                 # online
    python3 scripts/sync_cves.py --offline       # uses data/cache/feed.json
    python3 scripts/sync_cves.py --min-severity High --days 60
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from html import unescape
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FEED_URL = (
    "https://chromereleases.googleblog.com/feeds/posts/default/"
    "-/Stable%20updates?alt=json&max-results=60"
)
SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

# [N/A][ 568719351 ] Critical CVE-2026-110922: Use after free in Prerender.
ENTRY_RE = re.compile(
    # Old advisories start with the reward ("[$55000]"), newer ones with
    # "[N/A]" or "[TBD]"; both are followed by [bug_id] Severity CVE: desc.
    r"\[\s*[^\[\]]*?\s*\]\s*\[\s*(?P<bug>\d{6,12})\s*\]\s*"
    r"(?P<severity>Critical|High|Medium|Low)\s+"
    r"(?P<cve>CVE-\d{4}-\d+):\s*(?P<desc>[^.]+)\."
)
# "updated to 155.0.8059.84" or, in milestone promotions,
# "Chrome 156.0.8078.47 (Linux)"
VERSION_RE = re.compile(
    r"(?:updated to|Chrome)\s+(?P<version>\d+\.\d+\.\d+\.\d+)"
)
# "Google is aware that an exploit for CVE-2024-0519 exists in the wild."
ITW_RE = re.compile(r"exploit for (?P<cve>CVE-\d{4}-\d+) exists in the wild", re.I)


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "chrome-cve-lab/0.1"})
    with urllib.request.urlopen(req, timeout=90) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_feed(offline: bool, since: str, page_size: int = 50) -> str:
    """Return a combined feed covering every stable update since `since`.

    The label feed only returns the newest page by default, so older releases
    are paged in with start-index until we cross the requested date.
    """
    cache = ROOT / "data" / "cache" / "feed.json"
    if offline:
        return cache.read_text()

    entries: list[dict] = []
    start = 1
    while True:
        page = _get_json(f"{FEED_URL}&max-results={page_size}&start-index={start}")
        batch = page.get("feed", {}).get("entry", [])
        if not batch:
            break
        entries.extend(batch)
        oldest = min(e.get("published", {}).get("$t", "") for e in batch)
        print(f"[.] feed page start={start} n={len(batch)} oldest={oldest[:10]}")
        if oldest[:10] < since:
            break
        start += page_size
        if start > 1000:
            break

    combined = {"feed": {"entry": entries}}
    raw = json.dumps(combined)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(raw)
    return raw


def strip_html(fragment: str) -> str:
    text = re.sub(r"<[^>]+>", " ", fragment)
    return re.sub(r"\s+", " ", unescape(text))


# --- brute-force / RCE relevance -------------------------------------------
#
# Chrome advisories are terse: "Use after free in V8". The bug class is the
# phrase before " in ", the component is the phrase after it. A memory-safety
# class is a prerequisite for browser RCE; the component tells us how directly
# it leads to code execution (renderer/JIT/GPU/browser IPC vs. a sandboxed
# feature that still needs a separate escape).
MEMORY_SAFETY = (
    "use after free",
    "use-after-free",
    "type confusion",
    "heap buffer overflow",
    "buffer overflow",
    "out of bounds",
    "out-of-bounds",
    "integer overflow",
    "memory corruption",
    "uninitialized",
    "double free",
    "wild pointer",
    "race condition",
)
RCE_DIRECT = (
    "v8", "javascript", "webassembly", "wasm", "skia", "angle", "webgl",
    "webgpu", "dawn", "gpu", "mojo", "ipc", "webcodecs", "webrtc",
    "media", "audio", "video", "pdf", "font", "harfbuzz", "freetype",
    "blink", "compositing", "canvas", "prerender", "navigation",
)


def classify(component: str) -> tuple[str, str]:
    """Return (rce_relevance, rationale) for an advisory description."""
    desc = component.lower()
    bug = next((b for b in MEMORY_SAFETY if b in desc), None)
    area = desc.split(" in ", 1)[1] if " in " in desc else desc
    if bug is None:
        return "low", f"not a memory-safety class: {component!r}"
    if bug in ("out of bounds", "out-of-bounds") and "read" in desc and "write" not in desc:
        return "low", "out-of-bounds read: info leak, not code execution by itself"
    if any(k in area for k in RCE_DIRECT):
        return "high", f"{bug} in {area}: direct code-execution path"
    return "medium", f"{bug} in {area}: needs a reachable trigger / extra primitive"


def parse(feed: dict, min_severity: str, days: int | None, since: str | None = None) -> list[dict]:
    now = datetime.now(timezone.utc)
    rows: list[dict] = []
    for entry in feed.get("feed", {}).get("entry", []):
        title = entry.get("title", {}).get("$t", "")
        if "Stable Channel Update for Desktop" not in title:
            continue
        published = entry.get("published", {}).get("$t", "")
        try:
            when = datetime.fromisoformat(published)
        except ValueError:
            continue
        if days is not None and (now - when).days > days:
            continue
        if since is not None and published[:10] < since:
            continue

        content = strip_html(entry.get("content", {}).get("$t", ""))
        version_match = VERSION_RE.search(content)
        version = version_match.group("version") if version_match else ""
        links = [l["href"] for l in entry.get("link", []) if l.get("rel") == "alternate"]

        exploited = {m.group("cve") for m in ITW_RE.finditer(content)}
        for m in ENTRY_RE.finditer(content):
            if SEVERITY_ORDER[m.group("severity")] < SEVERITY_ORDER[min_severity]:
                continue
            component = m.group("desc").strip()
            relevance, rationale = classify(component)
            rows.append(
                {
                    "cve": m.group("cve"),
                    "severity": m.group("severity"),
                    "component": component,
                    "bug_id": m.group("bug"),
                    "fixed_version": version,
                    "release_date": published[:10],
                    "advisory": links[0] if links else "",
                    "rce_relevance": relevance,
                    "rce_rationale": rationale,
                    "exploited_in_wild": m.group("cve") in exploited,
                }
            )
    # de-duplicate keeping the most recent advisory
    seen: dict[str, dict] = {}
    for row in rows:
        seen.setdefault(row["cve"], row)
    return sorted(seen.values(), key=lambda r: (r["release_date"], r["cve"]), reverse=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", help="use data/cache/feed.json")
    ap.add_argument("--min-severity", default="Critical", choices=SEVERITY_ORDER)
    ap.add_argument("--days", type=int, default=None, help="window in days (default: all)")
    ap.add_argument("--since", default=None, help="only releases on/after YYYY-MM-DD")
    ap.add_argument("--out", default=str(ROOT / "data" / "cves.json"))
    ap.add_argument("--rce-only", action="store_true", help="write only RCE-relevant rows")
    ap.add_argument("--priority", action="store_true",
                    help="exploited-in-the-wild plus Critical memory-safety only")
    args = ap.parse_args()

    feed = json.loads(fetch_feed(args.offline, args.since or "2023-10-01"))
    rows = parse(feed, args.min_severity, args.days, args.since)
    if args.rce_only:
        rows = [r for r in rows if r["rce_relevance"] in ("high", "medium")
                or r.get("exploited_in_wild")]
    if args.priority:
        rows = [r for r in rows if r.get("exploited_in_wild")
                or (r["severity"] == "Critical" and r["rce_relevance"] in ("high", "medium"))]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n")
    counts: dict[str, int] = {}
    for r in rows:
        counts[r.get("rce_relevance", "?")] = counts.get(r.get("rce_relevance", "?"), 0) + 1
    print(f"[+] {len(rows)} CVEs ({args.min_severity}+) -> {out}  relevance={counts}")
    for r in rows[:10]:
        print(f"    {r['release_date']} {r['severity']:<8} {r['cve']} {r['component']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
