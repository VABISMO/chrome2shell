# chrome-cve-lab

Laboratorio reproducible para estudiar y **verificar** los CVEs críticos de
Google Chrome, usando exclusivamente información pública: avisos oficiales,
bug IDs de crbug.com y los *fix commits*.

> **Alcance:** laboratorio defensivo de *crash-only*. No contiene exploits, no
> busca RCE ni evasión de sandbox. El objetivo es responder a una pregunta
> concreta: *¿se puede reproducir el fallo con la build afectada y confirmar que
> desaparece con la parcheada?*

---

## TL;DR — qué hemos encontrado

En las dos últimas releases estables (15 y 20 de octubre de 2026) hay
**7 CVEs marcados `Critical`** por el Chrome team:

| CVE | Componente | Tipo | Bug ID | Fix commit | Reproducible |
|-----|-----------|------|--------|-----------|--------------|
| CVE-2026-110922 | Prerender | UAF (browser) | 568719351 | `d50992ebe4` | ⚠️ requiere BFCache+SW |
| CVE-2026-113341 | Skia / Ganesh | UAF (driver) | 569165786 | `02b14267` (skia) | ❌ hardware Imagination |
| CVE-2026-113279 | Accessibility | Mem. corruption | 570093145 | `83ce9f18d7` | 🧪 stress (a11y) |
| CVE-2026-113072 | CSS / LCP | Mem. corruption | 570638836 | `73dd2febfa` | ✅ comportamiento |
| CVE-2026-113280 | Paint / caret | Mem. corruption | 570740320 | `3ab9f85874` | 🧪 stress (paint) |
| CVE-2026-113271 | Accessibility | UAF (StringImpl) | 571618833 | `15248c94bc` | 🧪 stress (a11y) |
| CVE-2026-113303 | WebRTC / audio | Mem. corruption | 574041825 | `e193ceb7de` | 🧪 stress (audio) |

**Hallazgo metodológico:** aunque los bugs de crbug.com siguen restringidos y no
hay PoCs públicos, el aviso publica el **bug ID** y el fix aterriza en un repo
público con `Fixed: <bug_id>` en el mensaje. Eso permite recuperar el parche
exacto y derivar la causa raíz. `scripts/find_fixes.py` lo automatiza: 7/7
localizados.

**Realidad sobre la reproducción:** 6 de los 7 son corrupciones de memoria que
en builds `release` (sin ASAN ni DCHECKs) no abortan de forma fiable. El
laboratorio sirve para (1) confirmar la ruta vulnerable, (2) comparar
vulnerable vs. parcheada y (3) servir de base para un build ASAN. Los detalles
por CVE están en [`findings/RESULTS.md`](findings/RESULTS.md).

---

## Estructura

```
chrome-cve-lab/
├── data/
│   ├── cves.json          # inventario generado desde el feed oficial
│   ├── fixes.json         # CVE -> fix commit + parche
│   └── cache/feed.json    # copia del feed (modo --offline)
├── scripts/
│   ├── sync_cves.py       # Chrome Releases RSS -> data/cves.json
│   ├── find_fixes.py      # bug ID -> fix commit -> patches/<CVE>.patch
│   └── fetch_chrome.py    # descarga Chrome for Testing de una version exacta
├── harness/
│   ├── oracle.mjs         # carga una URL y detecta crash (renderer/browser)
│   └── run-case.mjs       # ejecuta un caso en vulnerable vs. parcheada
├── cases/<CVE>/           # case.json + testcase.html + README con la causa raiz
├── patches/               # parches de los fixes (evidencia)
└── findings/              # resultados crudos y RESULTS.md
```

## Requisitos

- Node.js ≥ 20 y `npm install` (solo `playwright-core`, sin navegadores).
- Python 3.10+.
- ~400 MB de disco por cada build de Chrome for Testing.
- No hace falta Docker. El binario de Chrome se ejecuta directamente.

## Uso

```bash
npm install

# 1. inventario de CVEs criticos (ultimos 60 dias)
python3 scripts/sync_cves.py --min-severity Critical --days 60

# 2. localizar parches (bug ID -> commit -> patch)
python3 scripts/find_fixes.py

# 3. descargar build vulnerable y primera parcheada
python3 scripts/fetch_chrome.py 155.0.8059.84 156.0.8078.47

# 4. ejecutar un caso (o todos)
node harness/run-case.mjs CVE-2026-113072
node harness/run-case.mjs --all
```

El oráculo devuelve `42` si detecta crash, `0` si no. Los resultados quedan en
`findings/<CVE>.json` y `findings/raw/`.

## Metodología

1. **Inventario** — el feed oficial de *Stable updates* incluye severidad, CVE,
   componente y bug ID.
2. **Parche** — `find_fixes.py` busca `repo:chromium/chromium <bug_id>` (y
   `google/skia`, `google/dawn`, `google/angle` como fallback) en la GitHub
   commit search API. El commit se guarda como `.patch`.
3. **Causa raíz** — se lee el diff (y su test de regresión, que suele describir
   la secuencia exacta).
4. **Testcase** — se traduce esa secuencia a HTML/JS ejecutable en el harness.
5. **Verificación diferencial** — mismo testcase en build vulnerable y en la
   primera parcheada. Se compara crash y comportamiento observable.

## Limitaciones (importante)

- **Sin ASAN.** Chrome for Testing son builds `release`. Un UAF puede no
  abortar. Para detección fiable hay que compilar Chromium con
  `is_asan=true is_debug=false` (o `is_msan`), lo que requiere ~100 GB y horas.
  El harness ya soporta apuntar a cualquier binario con `case.json -> browser`.
- **Bugs de driver/hardware.** CVE-2026-113341 vive en el driver Imagination;
  sin ese hardware no se reproduce.
- **Bugs de browser process.** Un UAF en el proceso browser se manifiesta como
  desconexión CDP, no como `page.on('crash')`; el oráculo lo clasifica como
  `browser-launch-or-connection`.
- **Timing.** Varios casos son carreras; se ejecutan con `iterations` y estrés,
  pero un resultado "sin crash" **no demuestra** que el bug no exista.

## Añadir un CVE nuevo

```bash
python3 scripts/sync_cves.py --min-severity High --days 30
python3 scripts/find_fixes.py --cve CVE-2026-XXXXX
mkdir cases/CVE-2026-XXXXX   # copia un case.json y su testcase.html
node harness/run-case.mjs CVE-2026-XXXXX
```

Ver [`docs/ADDING_CVES.md`](docs/ADDING_CVES.md).

## Referencias

- Chrome Releases: <https://chromereleases.googleblog.com/>
- Chrome Security (severity guidelines): <https://www.chromium.org/developers/severity-guidelines/>
- Chrome for Testing: <https://googlechromelabs.github.io/chrome-for-testing/>
- NVD: <https://nvd.nist.gov/>

## Aviso

Uso exclusivamente en un entorno propio y aislado. No apuntes el harness a
sitios de terceros ni distribuyas los testcases como exploits.
