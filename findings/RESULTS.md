# Resultados del laboratorio

Fecha: 2026-10-24
Builds usadas:

| Rol | Versión | Origen |
|-----|---------|--------|
| Afectada (6 CVEs del 20-oct) | 155.0.8059.84 | Chrome for Testing |
| Primera parcheada | 156.0.8078.47 | Chrome for Testing |
| Afectada (CVE-2026-110922) | 155.0.8059.79 | Chrome for Testing |
| Chromium del sistema (pruebas iniciales) | 155.0.8059.39 | distro |

---

## 1. Inventario

`data/cves.json` contiene **34 CVEs `Critical`** publicados entre el 2026-08-24
y el 2026-10-20. Los 7 más recientes (dos últimas releases estables) son los
que se han convertido en casos ejecutables.

La severidad que importa es la de Chromium (`Critical` en el aviso). NVD suele
puntuar más bajo y con retraso; ejemplo: CVE-2026-110922 es `Critical` para
Chrome y CVSS 8.8 (`HIGH`) en NVD. No son contradictorios: miden cosas
distintas (impacto potencial dentro del sandbox vs. puntuación genérica).

## 2. Parches recuperados (7/7)

| CVE | Bug | Repo | Commit | Tema |
|-----|-----|------|--------|------|
| CVE-2026-110922 | 568719351 | chromium | `d50992ebe4` | UAF de `NavigationRequest` en checks de prerender |
| CVE-2026-113341 | 569165786 | skia | `02b14267cb` | workaround FBO Imagination en Ganesh |
| CVE-2026-113279 | 570093145 | chromium | `83ce9f18d7` | image maps en `AXObjectCacheImpl` |
| CVE-2026-113072 | 570638836 | chromium | `73dd2febfa` | pseudo-elementos en LCP |
| CVE-2026-113280 | 570740320 | chromium | `3ab9f85874` | `FrameCaret::PaintCaret` y layout sucio |
| CVE-2026-113271 | 571618833 | chromium | `15248c94bc` | referencia a `title` en `AXNodeObject` |
| CVE-2026-113303 | 574041825 | chromium | `e193ceb7de` | `initialized_` sin lock en `WebRtcAudioDeviceImpl` |

Los diffs completos están en `patches/`. En 6 de 7 casos el commit incluye el
test de regresión, que ha servido para derivar el testcase.

## 3. Ejecución diferencial

Comando:

```bash
node harness/run-case.mjs --all
```

| CVE | Vulnerable (155.0.8059.84) | Parcheada (156.0.8078.47) | Veredicto |
|-----|---------------------------|----------------------------|-----------|
| CVE-2026-113072 | `entry.element` = `::before` | `entry.element` = `null` | **diferencia-conductual** |
| CVE-2026-113279 | 800 iteraciones, sin crash | 800, sin crash | sin crash |
| CVE-2026-113271 | 700 iteraciones, sin crash | 700, sin crash | sin crash |
| CVE-2026-113280 | 1500 frames, sin crash | 1500, sin crash | sin crash |
| CVE-2026-113303 | 120 ciclos, sin crash | 120, sin crash | sin crash |
| CVE-2026-110922 | — | — | bloqueado (secuencia BFCache/SW) |
| CVE-2026-113341 | — | — | no reproducible (driver Imagination) |

### CVE-2026-113072: única diferencia observable

Es el resultado más sólido del laboratorio. El mismo testcase, ejecutado contra
las dos builds oficiales, da:

```json
// 155.0.8059.84 (vulnerable)
{"hasElement": true, "isTargetDiv": false, "tagName": "::before",
 "ctor": "Element", "parentTag": "DIV"}

// 156.0.8078.47 (parcheada)
{"hasElement": false, "isTargetDiv": false, "tagName": null,
 "ctor": null, "parentTag": null}
```

En 155 el observador LCP recibe el pseudo-elemento; en 156
`Performance::CanExposeNode()` lo filtra y `element` es `null`. Esto demuestra
que la ruta vulnerable existe y que el parche la corta. No demuestra por sí solo
la corrupción de memoria: para eso hace falta ASAN.

### Resto de casos

Los casos de accesibilidad, caret y WebRTC ejecutan la ruta vulnerable (a11y
forzada con `--force-renderer-accessibility`, dispositivo de audio falso) pero
**no abortan en builds release**. Es lo esperable:

- UAF de `StringImpl` (113271) y de objetos AX (113279): el heap rara vez
  colisiona sin ASAN.
- Reentrada de layout en paint (113280): requiere DCHECK/ASAN o timing exacto.
- Carrera del hilo de audio (113303): necesita backend de audio real y TSAN.

Un "sin crash" aquí **no invalida** el CVE; solo indica que el entorno de
detección es demasiado débil.

## 4. Limitaciones y siguientes pasos

1. **Build ASAN.** Es el siguiente paso con mejor relación coste/beneficio.
   `docs/ADDING_CVES.md` describe cómo compilar `is_asan=true`. Con ASAN, los
   casos 113271/113279/113280/113303 tienen muchas más probabilidades de
   reportar el uso después de free.
2. **CVE-2026-110922.** Requiere un servidor que bloquee respuestas, Speculation
   Rules y activación de Service Worker. Se puede adaptar el test del parche a
   un test de navegador (`content_unittests`) en vez de intentarlo desde HTML.
3. **CVE-2026-113341.** Sin GPU Imagination no hay reproducción posible. El
   valor está en el análisis del workaround y su comparación con
   `GLES2DecoderImpl`.
4. **Falsos negativos.** Los casos de carrera se ejecutan un número limitado de
   iteraciones. Aumentar `iterations` y ejecutar en paralelo mejora la tasa de
   detección, pero no la garantiza.
