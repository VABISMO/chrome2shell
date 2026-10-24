#!/usr/bin/env python3
"""Locate the fix commit for a CVE from its crbug.com bug ID.

Chrome advisories publish the bug ID (e.g. 568719351) even while the bug stays
restricted. The fix lands in a public repository and its message contains
"Fixed: <bug_id>" (or "Bug: b/<bug_id>" in Skia), so the exact patch can be
recovered with the GitHub commit search API.

Some components (V8, Dawn, Skia, ANGLE) are vendored submodules: the matching
chromium commit is often only an *autoroll* of the submodule range. A roll does
not contain the root-cause diff, so this script follows it into the submodule
and picks the individual commit that references the bug.

Usage:
    python3 scripts/find_fixes.py                 # everything in data/cves.json
    python3 scripts/find_fixes.py --cve CVE-2026-110922
    python3 scripts/find_fixes.py --no-patches    # metadata only

Output:
    data/fixes.json
    patches/<CVE>.patch        # root-cause diff when resolvable
    patches/<CVE>.roll.patch   # chromium autoroll, kept as provenance
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# repositories where the fix may land, in order of likelihood
REPOS = [
    "chromium/chromium",
    "google/skia",
    "google/dawn",
    "google/angle",
    "v8/v8",
]
# search API without a token: 10 req/min
DELAY_S = 7.0

ROLL_RE = re.compile(
    r"^Roll (?P<module>V8|Dawn|Skia|ANGLE) from (?P<from>[0-9a-f]{7,40}) "
    r"to (?P<to>[0-9a-f]{7,40})",
    re.I,
)
SUB_REPO = {"v8": "v8/v8", "dawn": "dawn/dawn"}
SUB_GIT = {
    "v8": "https://chromium.googlesource.com/v8/v8",
    "dawn": "https://dawn.googlesource.com/dawn",
}


def gh_search(repo: str, bug_id: str) -> list[dict]:
    url = (
        "https://api.github.com/search/commits"
        f"?q=repo:{repo}+{bug_id}&per_page=100"
    )
    out = subprocess.run(
        ["curl", "-sS", "-H", "Accept: application/vnd.github+json", url],
        capture_output=True,
        text=True,
    ).stdout
    try:
        return json.loads(out).get("items", [])
    except json.JSONDecodeError:
        return []


def gh_patch(repo: str, sha: str) -> str:
    url = f"https://github.com/{repo}/commit/{sha}.patch"
    return subprocess.run(
        ["curl", "-sSL", url], capture_output=True, text=True
    ).stdout


def googlesource_log(repo: str, start: str, end: str) -> list[dict]:
    """Commits in start..end from a *.googlesource.com repository."""
    url = f"{repo}/+log/{start}..{end}?format=JSON"
    out = subprocess.run(
        ["curl", "-sS", url], capture_output=True, text=True
    ).stdout
    try:
        data = json.loads(out[out.index("{") :])
    except (ValueError, json.JSONDecodeError):
        return []
    return [
        {
            "sha": c["commit"],
            "subject": c["message"].splitlines()[0],
            "message": c["message"],
            "date": c["committer"]["time"] if "committer" in c else "",
        }
        for c in data.get("log", [])
    ]


def score(message: str, bug_id: str) -> int:
    """Rank a candidate commit as the root-cause fix."""
    subject = message.splitlines()[0]
    s = 0
    if f"Fixed: {bug_id}" in message:
        s += 60
    if f"Bug: {bug_id}" in message:
        s += 50
    if f"chromium:{bug_id}" in message:
        s += 50
    if re.search(rf"\b{bug_id}\b", message):
        s += 10
    if subject.startswith("[test]") or "regress-crbug" in subject:
        s -= 40
    if subject.lower().startswith("roll "):
        s -= 30
    if re.search(r"move .*(regression )?tests? into public", subject, re.I):
        s -= 35
    # Test-bundle commits list dozens of bugs; the root cause references one.
    if len(re.findall(r"^Bug: ", message, re.M)) > 3:
        s -= 25
    return s


def as_hit(repo: str, item: dict) -> dict:
    msg = item.get("message") or item.get("commit", {}).get("message", "")
    return {
        "repo": repo,
        "sha": item["sha"],
        "subject": msg.splitlines()[0],
        "message": msg,
        "date": item.get("date")
        or item.get("commit", {}).get("author", {}).get("date", ""),
        "url": f"https://github.com/{repo}/commit/{item['sha']}",
    }


def pick(entries: list[dict], bug_id: str) -> dict | None:
    if not entries:
        return None
    return max(
        entries,
        key=lambda e: score(e.get("message") or e.get("subject", ""), bug_id),
    )


def resolve_roll(hit: dict, bug_id: str) -> dict | None:
    """Follow an autoroll into the vendored submodule and return the real fix."""
    m = ROLL_RE.match(hit["subject"])
    if not m:
        return None
    module = m.group("module").lower()
    if module not in SUB_GIT:
        return None

    entries = googlesource_log(SUB_GIT[module], m.group("from"), m.group("to"))
    best = pick(entries, bug_id)
    if not best or score(best["message"], bug_id) <= 0:
        # The fix may predate the roll that merely carries its test. Search the
        # submodule history directly for the bug id.
        repo = SUB_REPO[module]
        hits = [as_hit(repo, it) for it in gh_search(repo, bug_id)]
        best = pick(hits, bug_id)
        if not best or score(best["message"], bug_id) <= 0:
            return None
        best["via_roll"] = hit["sha"]
        best["roll_range"] = f"{m.group('from')}..{m.group('to')}"
        return best

    repo = SUB_REPO[module]
    return {
        "repo": repo,
        "sha": best["sha"],
        "subject": best["subject"],
        "date": best["date"],
        "url": f"https://github.com/{repo}/commit/{best['sha']}",
        "via_roll": hit["sha"],
        "roll_range": f"{m.group('from')}..{m.group('to')}",
    }


def find(bug_id: str) -> tuple[dict | None, dict | None]:
    """Return (best commit, roll commit) for a bug id."""
    candidates: list[dict] = []
    for repo in REPOS:
        items = gh_search(repo, bug_id)
        hits = [as_hit(repo, it) for it in items]
        candidates.extend(hits)
        best = pick(hits, bug_id)
        if (
            best
            and score(best["message"], bug_id) >= 40
            and not best["subject"].lower().startswith("roll ")
        ):
            break  # strong direct hit in this repo, no need to try the rest
        time.sleep(DELAY_S)

    if not candidates:
        return None, None
    best = pick(candidates, bug_id)
    roll = best if best["subject"].lower().startswith("roll ") else None

    if roll:
        root = resolve_roll(roll, bug_id)
        if root:
            return root, roll

    # The search may also surface the real fix next to a roll; prefer it.
    direct = [
        c
        for c in candidates
        if not c["subject"].lower().startswith("roll ")
        and score(c["message"], bug_id) > 0
    ]
    if direct:
        return pick(direct, bug_id), roll
    return roll, roll


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cve", action="append", help="limit to one or more CVEs")
    ap.add_argument("--no-patches", action="store_true")
    ap.add_argument("--out", default=str(ROOT / "data" / "fixes.json"))
    args = ap.parse_args()

    cves = json.loads((ROOT / "data" / "cves.json").read_text())
    if args.cve:
        cves = [c for c in cves if c["cve"] in set(args.cve)]

    fixes: dict[str, dict] = {}
    out_path = Path(args.out)
    if out_path.exists():
        # Incremental runs must not drop CVEs resolved earlier.
        try:
            fixes = json.loads(out_path.read_text())
        except json.JSONDecodeError:
            fixes = {}
    patch_dir = ROOT / "patches"
    patch_dir.mkdir(exist_ok=True)

    for i, row in enumerate(cves):
        cve, bug = row["cve"], row["bug_id"]
        hit, roll = find(bug)

        entry: dict = {"bug_id": bug, "fix": hit}
        if hit and roll and hit["sha"] != roll["sha"]:
            entry["provenance"] = {"roll": roll}

        if hit:
            print(f"[+] {cve}  {hit['repo']}  {hit['sha'][:10]}  {hit['subject'][:70]}")
            if not args.no_patches:
                patch = gh_patch(hit["repo"], hit["sha"])
                if hit.get("via_roll"):
                    (patch_dir / f"{cve}.roll.patch").write_text(
                        gh_patch("chromium/chromium", hit["via_roll"])
                    )
                    entry["roll_patch"] = f"patches/{cve}.roll.patch"
                (patch_dir / f"{cve}.patch").write_text(patch)
                hit["patch"] = f"patches/{cve}.patch"
                print(f"    -> patches/{cve}.patch ({len(patch)} bytes)")
                if entry.get("roll_patch"):
                    print(f"    -> {entry['roll_patch']} (autoroll provenance)")
        else:
            print(f"[-] {cve}  bug {bug}: no public fix could be located")
        fixes[cve] = entry
        if i < len(cves) - 1:
            time.sleep(DELAY_S)

    Path(args.out).write_text(json.dumps(fixes, indent=2, ensure_ascii=False) + "\n")
    print(f"[+] wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
