# Añadir un CVE al laboratorio

## 1. Inventario

```bash
python3 scripts/sync_cves.py --min-severity High --days 30
```

Genera `data/cves.json` desde el feed oficial. Campos: `cve`, `severity`,
`component`, `bug_id`, `fixed_version`, `release_date`, `advisory`.

## 2. Localizar el parche

```bash
python3 scripts/find_fixes.py --cve CVE-2026-XXXXX
```

- Busca `repo:<repo> <bug_id>` en la GitHub commit search API.
- Repos probados en orden: `chromium/chromium`, `google/skia`, `google/dawn`,
  `google/angle`.
- Guarda el commit en `data/fixes.json` y el diff en `patches/<CVE>.patch`.

Si no aparece, el fix puede estar en otro repo (p. ej. `google/webrtc`) o aún no
ser público. Añade el repo a `REPOS` en el script.

## 3. Leer la causa raíz

Abre el `.patch`. Los parches de seguridad suelen incluir un test de regresión
cuyo nombre y comentarios describen la secuencia exacta. Ese test es la mejor
especificación del PoC.

## 4. Crear el caso

```
cases/CVE-2026-XXXXX/
├── case.json       # builds, flags, timeout, estado
├── testcase.html   # HTML/JS que ejercita la ruta vulnerable
└── README.md       # causa raíz, diff relevante, resultado
```

`case.json`:

```json
{
  "cve": "CVE-2026-XXXXX",
  "name": "descripcion corta",
  "vulnerable": "155.0.8059.84",
  "fixed": "156.0.8078.47",
  "entry": "testcase.html",
  "timeoutMs": 30000,
  "iterations": 2,
  "flags": ["--force-renderer-accessibility"],
  "status": "stress",
  "expectation": "que deberia observarse"
}
```

Estados:

| status | significado |
|--------|-------------|
| `behavioral` | se compara comportamiento observable, no crash |
| `stress` | se buscan crashes por repeticion/carrera |
| `blocked` | falta un ingrediente (red, SW, timing) |
| `not-reproducible` | depende de hardware/driver |

## 5. Reglas para el testcase

- Publica el veredicto en `window.__LAB_RESULT` (JSON serializable).
- No bloquear el hilo principal de forma indefinida; usa `setTimeout` de
  fallback.
- Nada de red externa: todo debe servirse desde `cases/<CVE>/` (el harness
  levanta un servidor estático en `127.0.0.1`).
- Si necesitas contexto seguro, `127.0.0.1` ya lo es.

## 6. Ejecutar

```bash
node harness/run-case.mjs CVE-2026-XXXXX
node harness/run-case.mjs CVE-2026-XXXXX --headed   # caret/paint real
```

Resultados: `findings/CVE-2026-XXXXX.json` (comparativa) y
`findings/raw/<CVE>.<vulnerable|fixed>.json` (crudo del oráculo).

## 7. Builds ASAN (opcional, para UAF reales)

Chrome for Testing no publica builds con sanitizers. Para detección fiable:

```bash
# requisitos: depot_tools, ~100 GB libres
fetch chromium
cd src && gn gen out/asan --args='is_debug=false is_asan=true is_component_build=false'
autoninja -C out/asan chrome
```

Luego apunta el caso a ese binario:

```json
{ "browser": "/ruta/a/src/out/asan/chrome" }
```
