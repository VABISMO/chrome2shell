.PHONY: install sync fixes fetch case all clean

CASE ?= CVE-2026-113072

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

# borra binarios descargados (no toca datos ni parches)
clean:
	rm -rf builds findings/raw
