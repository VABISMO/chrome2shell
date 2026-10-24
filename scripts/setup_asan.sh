#!/usr/bin/env bash
# Prepara un checkout de Chromium y compila `chrome` con AddressSanitizer.
#
# Esto NO se ejecuta en el laboratorio por defecto: requiere ~100-150 GB libres,
# 16 GB+ de RAM y varias horas. Es el paso necesario para caracterizar los UAF
# del informe de explotabilidad.
#
# Uso:
#   ./scripts/setup_asan.sh 155.0.8059.84
#   ./scripts/setup_asan.sh 156.0.8078.47 ~/chromium
#
# Requisitos: git, python3, y las dependencias de Chromium
# (https://chromium.googlesource.com/chromium/src/+/main/docs/linux/build_instructions.md)
set -euo pipefail

VERSION="${1:-155.0.8059.84}"
WORK="${2:-$HOME/chromium}"
SRC="$WORK/src"
OUT="$SRC/out/asan"

say() { printf '\n\033[1m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }

command -v git >/dev/null || { echo "falta git"; exit 1; }
command -v python3 >/dev/null || { echo "falta python3"; exit 1; }

mkdir -p "$WORK"

if [ ! -d "$WORK/depot_tools" ]; then
  say "clonando depot_tools"
  git clone --depth 1 https://chromium.googlesource.com/chromium/tools/depot_tools.git "$WORK/depot_tools"
fi
export PATH="$WORK/depot_tools:$PATH"

if [ ! -d "$SRC" ]; then
  say "fetch chromium (esto descarga decenas de GB)"
  cd "$WORK"
  fetch --nohooks --no-history chromium
else
  say "checkout existente en $SRC"
fi

cd "$SRC"

say "checkout $VERSION"
# Las releases de Chrome llevan tag en el repo de Chromium.
git fetch origin "refs/tags/$VERSION:refs/tags/$VERSION" --depth 1 || true
git checkout -f "$VERSION"

say "sincronizando dependencias"
gclient sync -D --with_branch_heads --with_tags

say "generando out/asan"
gn gen "$OUT" --args='
  is_debug=false
  is_official_build=false
  is_asan=true
  is_component_build=false
  symbol_level=1
  blink_symbol_level=1
  enable_nacl=false
  use_lld=true
  treat_warnings_as_errors=false
'

say "compilando chrome con ASAN (horas)"
autoninja -C "$OUT" chrome

say "listo: $OUT/chrome"
echo
echo "Apunta un caso a ese binario:"
echo "  echo '{\"browser\": \"$OUT/chrome\"}' > /tmp/override.json"
echo "  # o edita cases/<CVE>/case.json y anade: \"browser\": \"$OUT/chrome\""
echo
echo "Ejecucion:"
echo "  ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1 \\"
echo "    node harness/run-case.mjs CVE-2026-113271"
