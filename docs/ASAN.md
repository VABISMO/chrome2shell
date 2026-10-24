# Build ASAN de Chromium

Chrome for Testing son builds `release`: un UAF puede no abortar nunca. Para
caracterizar de verdad los fallos del informe de explotabilidad hace falta un
build con AddressSanitizer.

## Coste realista

| Recurso | Estimación |
|---------|-----------|
| Disco | 100–150 GB (checkout + out/asan) |
| RAM | 16 GB mínimo; 32 GB recomendable para enlazar |
| Tiempo | 2–6 h según CPU (primer build) |
| Red | ~50–80 GB de descarga |

No es un paso que se pueda hacer "en un rato". Planifícalo.

## Automático

```bash
chmod +x scripts/setup_asan.sh
./scripts/setup_asan.sh 155.0.8059.84
```

El script clona `depot_tools`, hace `fetch chromium`, checkout del tag de la
versión, `gclient sync`, genera `out/asan` con `is_asan=true` y compila.

## Manual

```bash
git clone --depth 1 https://chromium.googlesource.com/chromium/tools/depot_tools.git
export PATH="$PWD/depot_tools:$PATH"

fetch --nohooks --no-history chromium
cd src
git fetch origin refs/tags/155.0.8059.84:refs/tags/155.0.8059.84 --depth 1
git checkout 155.0.8059.84
gclient sync -D --with_branch_heads --with_tags

gn gen out/asan --args='
  is_debug=false
  is_official_build=false
  is_asan=true
  is_component_build=false
  symbol_level=1
  blink_symbol_level=1
'

autoninja -C out/asan chrome
```

## Ejecutar un caso contra el build ASAN

Edita `cases/<CVE>/case.json` y añade la ruta absoluta:

```json
{ "browser": "/home/tu-usuario/chromium/src/out/asan/chrome" }
```

O pasa las rutas por CLI:

```bash
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1 \
  node harness/run-case.mjs CVE-2026-113271 \
  --vuln /home/tu-usuario/chromium/src/out/asan/chrome \
  --fixed builds/156.0.8078.47/chrome-linux64/chrome
```

> El build ASAN ya contiene el fix si compilas 156. Para comparar de verdad,
> compila la versión **vulnerable** con ASAN y ejecuta el caso solo contra ella
> (`--fixed` puede apuntar a la build release parcheada; lo que importa es ver
> el reporte ASAN en la vulnerable).

## Qué buscar en el reporte

```
ERROR: AddressSanitizer: heap-use-after-free on address 0x...
READ of size 8 at 0x... thread T0
    #0 ... AXObjectCacheImpl::RemoveSubtreeInternal()
freed by thread T0 here:
    #0 ... operator delete
    #1 ... AXObject::...
previously allocated by thread T0 here:
    #0 ... operator new
```

Preguntas que responde:

1. ¿Es un UAF real o solo un estado inconsistente?
2. Tipo y tamaño del objeto liberado (clave para PartitionAlloc).
3. ¿La pila de free es determinista o depende de timing?
4. ¿El acceso es lectura o escritura?

Con eso se actualiza `findings/EXPLOITABILITY.md` con datos, no con
especulación.

## Alternativa para la carrera de WebRTC

CVE-2026-113303 es una carrera de datos: el sanitizer correcto es **TSAN**
(`is_tsan=true`), no ASAN. Compila `out/tsan` con los mismos pasos cambiando
`is_asan=true` por `is_tsan=true`.

## Notas

- `is_component_build=false` es obligatorio para ASAN en Linux.
- Si el enlace agota memoria, baja `symbol_level` a 0 o usa `use_thin_lto=false`.
- No ejecutes el binario ASAN con `--no-sandbox` salvo en el contenedor del lab.
