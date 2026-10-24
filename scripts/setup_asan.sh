#!/usr/bin/env bash
# Prepare a Chromium checkout and build `chrome` with AddressSanitizer.
#
# This does NOT run in the lab by default: it needs ~100-150 GB free, 16 GB+ of
# RAM and several hours. It is the step required to characterize the UAFs in the
# exploitability report.
#
# Usage:
#   ./scripts/setup_asan.sh 155.0.8059.84
#   ./scripts/setup_asan.sh 156.0.8078.47 ~/chromium
#
# Requirements: git, python3, and Chromium's build dependencies
# (https://chromium.googlesource.com/chromium/src/+/main/docs/linux/build_instructions.md)
set -euo pipefail

VERSION="${1:-155.0.8059.84}"
WORK="${2:-$HOME/chromium}"
TARGET="${TARGET:-chrome}"          # content_browsertests for the 110922 test
JOBS="${JOBS:-$(nproc)}"
SRC="$WORK/src"
OUT="$SRC/out/asan"

say() { printf '\n\033[1m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }

command -v git >/dev/null || { echo "missing git"; exit 1; }
command -v python3 >/dev/null || { echo "missing python3"; exit 1; }

mkdir -p "$WORK"

if [ ! -d "$WORK/depot_tools" ]; then
  say "cloning depot_tools"
  git clone --depth 1 https://chromium.googlesource.com/chromium/tools/depot_tools.git "$WORK/depot_tools"
fi
export PATH="$WORK/depot_tools:$PATH"

if [ ! -d "$SRC" ]; then
  say "fetch chromium (this downloads tens of GB)"
  cd "$WORK"
  fetch --nohooks --no-history chromium
else
  say "existing checkout at $SRC"
fi

cd "$SRC"

say "checking out $VERSION"
# Chrome releases are tagged in the Chromium repo.
git fetch origin "refs/tags/$VERSION:refs/tags/$VERSION" --depth 1 || true
git checkout -f "$VERSION"

say "syncing dependencies"
gclient sync -D --with_branch_heads --with_tags

say "generating out/asan"
gn gen "$OUT" --args="
  is_debug=false
  is_official_build=false
  is_asan=true
  is_component_build=false
  symbol_level=1
  blink_symbol_level=1
  enable_nacl=false
  use_lld=true
  use_thin_lto=false
  treat_warnings_as_errors=false
"

# 15 GB of RAM cannot link Chromium with the default -j on 18 cores; lld with
# ThinLTO off keeps peak memory low enough, but the job count still has to be
# capped by the caller (JOBS=8 ./scripts/setup_asan.sh ...).
say "building $TARGET with ASAN (hours, -j $JOBS)"
autoninja -j "$JOBS" -C "$OUT" "$TARGET"

say "done: $OUT/$TARGET"
echo
echo "Point a case at that binary:"
echo "  # or edit cases/<CVE>/case.json and add: \"browser\": \"$OUT/chrome\""
echo
echo "Run it:"
echo "  ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1 \\"
echo "    node harness/run-case.mjs CVE-2026-113271"
