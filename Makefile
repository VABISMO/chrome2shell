.PHONY: install sync sync-rce sync-priority fixes fetch case all repro-110922 selfdrive-110922 clean

CASE ?= CVE-2026-113072
VULN ?= builds/155.0.8059.84/chrome-linux64/chrome
SINCE ?= 2023-10-01

install:
	npm install --no-audit --no-fund

# full High/Critical inventory (three years by default)
sync:
	python3 scripts/sync_cves.py --since $(SINCE) --min-severity High

# RCE-relevant subset and highest-priority backlog
sync-rce:
	python3 scripts/sync_cves.py --since $(SINCE) --min-severity High --rce-only --out data/rce_cves.json

sync-priority:
	python3 scripts/sync_cves.py --since $(SINCE) --min-severity High --priority --out data/rce_priority.json

fixes:
	python3 scripts/find_fixes.py

fetch:
	python3 scripts/fetch_chrome.py 155.0.8059.84 156.0.8078.47

case:
	node harness/run-case.mjs $(CASE)

all:
	node harness/run-case.mjs --all

# CVE-2026-110922: browser-process UAF reproducer (crash-only, dynamic server).
# Playwright driver: control only, CDP disables prerendering.
repro-110922:
	node harness/repro-110922.mjs --browser $(VULN) --attempts 2 --delays 0,25,100

# CVE-2026-110922: CDP-free driver that actually creates a prerender host.
selfdrive-110922:
	node harness/selfdrive-110922.mjs --browser $(VULN) --attempts 2 --delay 0 --count 2

# removes downloaded binaries (leaves data and patches untouched)
clean:
	rm -rf builds findings/raw
