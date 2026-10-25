.PHONY: install sync sync-rce sync-priority fixes fetch fetch-85046 case leak rce cores all repro-110922 selfdrive-110922 selfdrive-110922-debug clean

CASE ?= CVE-2026-113072
VULN ?= builds/155.0.8059.84/chrome-linux64/chrome
SINCE ?= 2023-10-01
CONNECTIONS ?= 1

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
	python3 scripts/fetch_chrome.py 155.0.8059.84 156.0.8078.47 --connections $(CONNECTIONS)

# CVE-2026-85046 pair: last vulnerable vs first patched V8 build
fetch-85046:
	python3 scripts/fetch_chrome.py 152.0.7977.75 152.0.7977.82 --connections $(CONNECTIONS)

# stage 1: crash / behaviour trigger, differentially (docs/EXPLOITATION.md)
case:
	node harness/run-case.mjs $(CASE)

# stage 2: leak PoC (cases/<CASE>/poc-leak.html)
leak:
	node harness/run-case.mjs $(CASE) --stage leak

# stage 3: RCE PoC (cases/<CASE>/poc-rce.html)
rce:
	node harness/run-case.mjs $(CASE) --stage rce

# stage 1 keeping the core dump + gdb report (docs/GDB.md)
cores:
	node harness/run-case.mjs $(CASE) --stage crash --cores --keep-core

all:
	node harness/run-case.mjs --all

# CVE-2026-110922: browser-process UAF reproducer (crash-only, dynamic server).
# Playwright driver: control only, CDP disables prerendering.
repro-110922:
	node harness/repro-110922.mjs --browser $(VULN) --attempts 2 --delays 0,25,100

# CVE-2026-110922: CDP-free driver that actually creates a prerender host.
selfdrive-110922:
	node harness/selfdrive-110922.mjs --browser $(VULN) --attempts 2 --delay 0 --count 2

# Same, keeping the core dump for manual gdb inspection (docs/GDB.md).
selfdrive-110922-debug:
	node harness/selfdrive-110922.mjs --browser $(VULN) --attempts 2 --delay 950 --count 2 --keep-core

# removes downloaded binaries (leaves data and patches untouched)
clean:
	rm -rf builds findings/raw
