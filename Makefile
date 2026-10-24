.PHONY: install sync fixes fetch case all repro-110922 clean

CASE ?= CVE-2026-113072
VULN ?= builds/155.0.8059.84/chrome-linux64/chrome

install:
	npm install --no-audit --no-fund

sync:
	python3 scripts/sync_cves.py --min-severity Critical --days 60

fixes:
	python3 scripts/find_fixes.py

fetch:
	python3 scripts/fetch_chrome.py 155.0.8059.84 156.0.8078.47

case:
	node harness/run-case.mjs $(CASE)

all:
	node harness/run-case.mjs --all

# CVE-2026-110922: browser-process UAF reproducer (crash-only, dynamic server)
repro-110922:
	node harness/repro-110922.mjs --browser $(VULN) --attempts 2 --delays 0,25,100

# removes downloaded binaries (leaves data and patches untouched)
clean:
	rm -rf builds findings/raw
