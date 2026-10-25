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
| CVE-2026-3910 | V8 type confusion (Maglev Phi untagging) | 146.0.7680.72 (flag confirmed ON via `--js-flags=--help`) vs .76 (also ON — CfT `.76` lacks the hotfix; advisory fixed point is `.75`, next CfT is `.80`) | 🧪 recon extensive: Maglev force solved (`%OptimizeMaglevOnNextCall`, status25),13 source-derived shapes (canary exact, static-type lies, peeled-loop backedge, OSR, spec-hoist, alternating) all round-trip — **corrupting shape not found**; needs V8 debug build (`--trace-maglev-phi-untagging` reaches only stderr, which renderers never emit) or the restricted bug repro | ⏳ | ⏳ chain write-primitive on hold | next session: d8/V8 debug build for pass-level visibility, or park for a self-contained OOB target |
| CVE-2026-3909 | Skia OOB write (atlas) | < 146.0.7680.80 | ⏳ | ⏳ | ⏳ | stage 1 trigger from the patch's test |
| CVE-2026-5281 | Dawn wire UAF | < 146.0.7680.177 | ⏳ | ⏳ | ⏳ | stage 1 trigger from the patch's test |
| CVE-2026-2441 | CSS font-feature-values UAF | < 145.0.7632.75 | ⏳ | ⏳ | ⏳ | evaluated as chain partner: UAF-*read* of the aliases vector (another leak, not a write) — parked | 
| CVE-2024-0519 | V8 fast last-property deletion → map-rollback OOB (in-the-wild) | 120.0.6099.109 + **d8 debug `-O0`** at `/home/cryptocalypse/v8dbg` (V8 @ `6f98fbe86a0d` = fix parent) | 🟢 d8 campaign ONLINE: rollback observed at machine level (gdb `-O0` exact lines, map ptr child→parent, notify=mark_unstable, only `kPrototypeCheckGroup` deopts); rounds 1–9 =42 shapes +2 state rounds: layout ALWAYS consistent (in-place map shrink `56→24` real; writer deopts 129→49 on mismatched store; canaries intact) | ⏳ | ⏳ self-contained RCE target | **round10: dependent-code matrix** (const/field-type deps surviving `NotifyLeafMapLayoutChange` × rollback+re-add × optimized readers on same-map objects, value+status tracked); instruments: `%DebugPrint` (stdout en d8) + gdb line breaks + `GetOptimizationStatus` |

## Conventions

- Stage entry per case lives in `cases/<CVE>/case.json -> stages.<stage> =
  {entry, status}`; `node harness/run-case.mjs <CVE> --stage <stage>` resolves
  it. Statuses here and in `case.json` must agree.
- Evidence files: `findings/raw/<CVE>.<stage>.<vulnerable|fixed>.json`, cores
  and `*.core.txt` when `--cores` is used.
- A stage is only 🟢 when the **patched build fails the same PoC**.
