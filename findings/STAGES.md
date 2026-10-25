# Stage tracker — crash → leak → RCE

One row per CVE, one column per stage, plus the next action. Update this file
in the same commit as the evidence it refers to.

Legend: 🟢 done · 🟡 partial (evidence exists, level short of complete) ·
🧪 in progress (path exercised, no result yet) · ⏳ pending (not started) ·
⛔ blocked (missing ingredient) · 🚫 out of scope (environment)

Methodology and exit criteria per stage: [`../docs/EXPLOITATION.md`](../docs/EXPLOITATION.md).
Builds: vulnerable `155.0.8059.84`, first patched `156.0.8078.47` (except
CVE-2026-110922: `155.0.8059.79` vs `155.0.8059.84`).

## October 2026 cases

| CVE | Class | Crash (1) | Leak (2) | RCE (3) | Next action |
|-----|-------|-----------|----------|---------|-------------|
| CVE-2026-113072 | LCP exposes `::before` | 🟡 behavioral difference (no fault; path proven on both builds) | 🟡 exposure level: `entry.element` returns a hidden `::before` node on 155, `null` on 156 | ⏳ | decide whether the exposed node can carry address-like data; otherwise close at exposure level and keep as regression test |
| CVE-2026-113279 | AX UAF (image maps) | 🧪 800 iterations, no fault in release | ⏳ | ⏳ | shape `AXObject` reuse of the freed slot; `gdb` breakpoint on the fix lines (`InvalidateChildren` / `ChildrenChangedWithCleanLayout`) |
| CVE-2026-113271 | dangling `AtomicString` ref | 🧪 700 iterations, no fault in release | ⏳ | ⏳ | force attribute-storage reallocation inside the same stack; hardware watchpoint on the freed `StringImpl` |
| CVE-2026-113280 | layout reentrancy in paint | 🧪 1500 frames, no fault in release | ⏳ | ⏳ | reproduce the patch's own sequence (dirty layout + caret); breakpoint `FrameCaret::PaintCaret` before/after the fix flag |
| CVE-2026-113303 | `WebRtcAudioDeviceImpl` race | 🧪 120 cycles, no fault in release | ⏳ | ⏳ | break the race deliberately: breakpoint the unsynchronized `initialized_` read and drive attach/teardown pairs |
| CVE-2026-110922 | browser-process `NavigationRequest` UAF | ⛔ synchronous eviction not schedulable from web content (0 crashes in 30+ attempts) | ⏳ blocked by stage 1 | ⏳ blocked by stage 1 | drive the patch's C++ regression test under `gdb` (`BeginNavigation` / `DidStartNavigation`), debug build, no sanitizer |
| CVE-2026-113341 | Imagination driver UAF | 🚫 no Imagination GPU/driver in this environment | 🚫 | 🚫 | analysis only: compare the workaround with `GLES2DecoderImpl` |

## In-the-wild backlog (RCE-ladder targets, patches recovered)

Patches are in `patches/`; builds fetched with `scripts/fetch_chrome.py`
(`--connections N` for slow links). Plans: [`../docs/EXPLOITATION.md`](../docs/EXPLOITATION.md) §5.

| CVE | Component | Vulnerable build needed | Crash (1) | Leak (2) | RCE (3) | Next action |
|-----|-----------|------------------------|-----------|----------|---------|-------------|
| CVE-2026-85046 | V8 type confusion (sort inlining) | 152.0.7977.75 vs 152.0.7977.82 | 🟢 done: differential = upstream mjsunit assertion via plain-JS Smi consumers (`JSON`/`join` decode pointers as numbers: `[8595714,…]` vs `[{},{}]`) | 🟢 done: **addrof**, level *leak* —10 values in cage range, same object→same value, neighbour pair→16 B delta; patched leaks 0 | 🟡 recon: rungs1–3 done; **fakeobj blocked** — parity wall;4 paths eliminated with evidence (object-store heals, major-GC reclaim, minor-GC/WB, double-union pre-rejected) | refined WB-timing test or JIT-schedule store path (`cases/CVE-2026-85046/README.md` §Stage 3) + no-flag trigger |
| CVE-2026-3910 | V8 Maglev phi untagging (write-barrier elision on Smi feedback) | 146.0.7680.72 (untagged_phis default ON) vs 155.0.8059.84 (OFF — post-fix) | 🟢 **REPRODUCED** — port of the public root-cause PoC (`poc-wb-uaf.html`): Maglev forced (status 25) → major GC promotes `o` → `trigger(0x10000000)` stores retagged young HeapNumber (0x50000000 > Smi range) WITHOUT write barrier → minor GC frees it → reading `o.x` during GC churn = deterministic renderer crash (**V8 fatal, core `ud2`**); phase-mapped: pre-big/post-big/post-minor publish clean, full run dies at the UAF read; 155 completes clean. Fixes d01d721bbcb6 + 433b2912c5c (`BuildCheckSmi` elidable — ABSENT in tree) + 7076ba135f (default off — ABSENT). Evidence: `findings/raw/CVE-2026-3910.crash.*.json` + cores, verdict=reproduced | 🧪 next: leak = reclaim freed 16B HeapNumber slot with sprayed doubles → `o.x` reads attacker bytes (marker) → bit-extract; then static-roots fake double array (huge length) = cage R/W | ⛓ same build carries 85046 addrof + 3910 UAF-write | next: stage 2 reclaim overlap immediately |
| CVE-2026-3909 | Skia OOB write (atlas) | < 146.0.7680.80 | 🧪 sweep built (`cases/CVE-2026-3909/testcase.html`, `--gpu` SwiftShader): 401 frames, LCD/gray flip, hinting=full, 700-glyph atlas pressure + emoji ARGB — no manifestation; root cause = `TextStrike` keyed by glyph-id only, but a natural same-glyph/two-format flip not found | ⏳ | ⏳ | canonical trigger is the patch's `AtlasOobTest` (crafted slug + strike data, format kARGB→kA8 switch) → needs a Skia `dm` build, or find the natural flip (SDF/resolveMaskFormat downgrade under atlas pressure) |
| CVE-2026-5281 | Dawn wire UAF | < 146.0.7680.177 | 🧪 8 cross-origin renderer teardowns with device+deep queue+presenting canvas in flight, GPU-process memory clobber after each kill, continuous native validation errors — no GPU death; wire confirmed present in binary (`DawnSpontaneousWireServer`); race is µs-callback vs 100ms+ teardown, outstanding-native-ref precondition unverified in Chrome | ⏳ | ⏳ | verify which object holds the native device ref past `~Server` in Chrome (SharedImage/canvas?), or drive Dawn's `WireDisconnectTests` semantics under gdb (Dawn unit-test build) |
| CVE-2026-2441 | CSS font-feature-values UAF | 145.0.7632.67 vs 145.0.7632.76 | 🟢 done: differential — vuln **SEGV 4/4 iter** (renderer crash, non-canonical deref; core: `rax=0x4055210000000000` = IEEE754 double bits deref'd as pointer → freed-buffer garbage), fixed = clean (3 legit entries, no crash). Evidence: `findings/raw/CVE-2026-2441.crash.*.json` + 4 cores | 🟢 done: UAF-read — after the free,24 foreign `@font-feature-values` maps (same size class) reclaim the bucket buffer; the stale iterator returns **foreign keys never present in the original map** (`f0x1`,`f13x2`, …) + empty slots = read-after-free of replaced memory. Evidence: `findings/raw/CVE-2026-2441.leak.vulnerable.json` | ⛔ read-only primitive (iteration source never writes) — standalone RCE not derivable; chain role = leak half; pointer-fragment refinement **attempted**: URLSearchParams / attribute arrays / SpaceSplitString sprays (64+128 B, {ptr,ptr} shapes) never taken — reclaim happens at `FontFeatureAliases`-object level only, whose value slots are authored u32 (needs fakeobj-level control to redirect) | next: park refinement; free slot only via chain (85046/3910 write) | 
| CVE-2024-0519 | V8 fast last-property deletion → map-rollback OOB (in-the-wild) | 120.0.6099.109 + **d8 debug `-O0`** at `/home/cryptocalypse/v8dbg` (V8 @ `6f98fbe86a0d` = fix parent) | 🟢 d8 campaign ONLINE: rollback observed at machine level (gdb `-O0` exact lines, map ptr child→parent, notify=mark_unstable, only `kPrototypeCheckGroup` deopts); rounds 1–9 =42 shapes +2 state rounds: layout ALWAYS consistent (in-place map shrink `56→24` real; writer deopts 129→49 on mismatched store; canaries intact) | ⏳ | ⏳ self-contained RCE target | **round10: dependent-code matrix** (const/field-type deps surviving `NotifyLeafMapLayoutChange` × rollback+re-add × optimized readers on same-map objects, value+status tracked); instruments: `%DebugPrint` (stdout en d8) + gdb line breaks + `GetOptimizationStatus` |

## Conventions

- Stage entry per case lives in `cases/<CVE>/case.json -> stages.<stage> =
  {entry, status}`; `node harness/run-case.mjs <CVE> --stage <stage>` resolves
  it. Statuses here and in `case.json` must agree.
- Evidence files: `findings/raw/<CVE>.<stage>.<vulnerable|fixed>.json`, cores
  and `*.core.txt` when `--cores` is used.
- A stage is only 🟢 when the **patched build fails the same PoC**.
