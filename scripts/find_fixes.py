#!/usr/bin/env python3
"""Localiza el fix commit de un CVE a partir de su bug ID de crbug.com.

Los avisos de Chrome publican el bug ID (p.ej. 568719351) aunque el bug siga
restringido. El fix aterriza en un repositorio publico y su mensaje contiene
"Fixed: <bug_id>" (o "Bug: b/<bug_id>" en Skia), por lo que se puede recuperar
el parche exacto con la GitHub commit search API.

Uso:
    python3 scripts/find_fixes.py                 # todos los de data/cves.json
    python3 scripts/find_fixes.py --cve CVE-2026-110922
    python3 scripts/find_fixes.py --no-patches    # solo metadatos

Salida:
    data/fixes.json
    patches/<CVE>.patch
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# repos donde puede aterrizar el fix, en orden de probabilidad
REPOS = ["chromium/chromium", "google/skia", "google/dawn", "google/angle"]
# search API sin token: 10 req/min
DELAY_S = 7.0


def gh_search(repo: str, bug_id: str) -> dict:
    url = f"https://api.github.com/search/commits?q=repo:{repo}+{bug_id}"
    out = subprocess.run(
        ["curl", "-sS", "-H", "Accept: application/vnd.github+json", url],
        capture_output=True,
        text=True,
    ).stdout
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"items": [], "message": out[:200]}


def gh_patch(repo: str, sha: str) -> str:
    url = f"https://github.com/{repo}/commit/{sha}.patch"
    return subprocess.run(["curl", "-sSL", url], capture_output=True, text=True).stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cve", action="append", help="limita a uno o varios CVE")
    ap.add_argument("--no-patches", action="store_true")
    ap.add_argument("--out", default=str(ROOT / "data" / "fixes.json"))
    args = ap.parse_args()

    cves = json.loads((ROOT / "data" / "cves.json").read_text())
    if args.cve:
        cves = [c for c in cves if c["cve"] in set(args.cve)]

    fixes: dict[str, dict] = {}
    patch_dir = ROOT / "patches"
    patch_dir.mkdir(exist_ok=True)

    for i, row in enumerate(cves):
        cve, bug = row["cve"], row["bug_id"]
        found = None
        for repo in REPOS:
            data = gh_search(repo, bug)
            items = data.get("items", [])
            if items:
                hit = items[0]
                found = {
                    "repo": repo,
                    "sha": hit["sha"],
                    "subject": hit["commit"]["message"].splitlines()[0],
                    "date": hit["commit"]["author"]["date"],
                    "url": hit["html_url"],
                }
                break
            time.sleep(DELAY_S)
        fixes[cve] = {"bug_id": bug, "fix": found}
        if found:
            print(f"[+] {cve}  {found['repo']}  {found['sha'][:10]}  {found['subject'][:70]}")
            if not args.no_patches:
                patch = gh_patch(found["repo"], found["sha"])
                (patch_dir / f"{cve}.patch").write_text(patch)
                found["patch"] = f"patches/{cve}.patch"
                print(f"    -> patches/{cve}.patch ({len(patch)} bytes)")
        else:
            print(f"[-] {cve}  bug {bug}: sin fix publico localizable")
        if i < len(cves) - 1:
            time.sleep(DELAY_S)

    Path(args.out).write_text(json.dumps(fixes, indent=2, ensure_ascii=False) + "\n")
    print(f"[+] escrito {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
