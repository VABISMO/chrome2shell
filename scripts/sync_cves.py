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
    r"\[\s*(?:N/A|TBD)\s*\]\s*\[\s*(?P<bug>\d{6,12})\s*\]\s*"
    r"(?P<severity>Critical|High|Medium|Low)\s+"
    r"(?P<cve>CVE-\d{4}-\d+):\s*(?P<desc>[^.]+)\."
)
# "updated to 155.0.8059.84" or, in milestone promotions,
# "Chrome 156.0.8078.47 (Linux)"
VERSION_RE = re.compile(
    r"(?:updated to|Chrome)\s+(?P<version>\d+\.\d+\.\d+\.\d+)"
)


def fetch_feed(offline: bool) -> str:
    cache = ROOT / "data" / "cache" / "feed.json"
    if offline:
        return cache.read_text()
    req = urllib.request.Request(FEED_URL, headers={"User-Agent": "chrome-cve-lab/0.1"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read().decode("utf-8")
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(raw)
    return raw


def strip_html(fragment: str) -> str:
    text = re.sub(r"<[^>]+>", " ", fragment)
    return re.sub(r"\s+", " ", unescape(text))


def parse(feed: dict, min_severity: str, days: int | None) -> list[dict]:
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

        content = strip_html(entry.get("content", {}).get("$t", ""))
        version_match = VERSION_RE.search(content)
        version = version_match.group("version") if version_match else ""
        links = [l["href"] for l in entry.get("link", []) if l.get("rel") == "alternate"]

        for m in ENTRY_RE.finditer(content):
            if SEVERITY_ORDER[m.group("severity")] < SEVERITY_ORDER[min_severity]:
                continue
            rows.append(
                {
                    "cve": m.group("cve"),
                    "severity": m.group("severity"),
                    "component": m.group("desc").strip(),
                    "bug_id": m.group("bug"),
                    "fixed_version": version,
                    "release_date": published[:10],
                    "advisory": links[0] if links else "",
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
    ap.add_argument("--out", default=str(ROOT / "data" / "cves.json"))
    args = ap.parse_args()

    feed = json.loads(fetch_feed(args.offline))
    rows = parse(feed, args.min_severity, args.days)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n")
    print(f"[+] {len(rows)} CVEs ({args.min_severity}+) -> {out}")
    for r in rows[:10]:
        print(f"    {r['release_date']} {r['severity']:<8} {r['cve']} {r['component']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
