# Lab results

Date: 2026-10-24
Scope: crash → leak → RCE with normal binary-debugging tools, no sanitizers
([`docs/EXPLOITATION.md`](../docs/EXPLOITATION.md); per-stage tracker:
[`STAGES.md`](STAGES.md)).
Builds used:

| Role | Version | Source |
|------|---------|--------|
| Affected (6 CVEs from Oct 20) | 155.0.8059.84 | Chrome for Testing |
| First patched | 156.0.8078.47 | Chrome for Testing |
| Affected (CVE-2026-110922) | 155.0.8059.79 | Chrome for Testing |
| Affected / first patched (CVE-2026-85046) | 152.0.7977.75 / 152.0.7977.82 | Chrome for Testing |
| System Chromium (initial checks) | 155.0.8059.39 | distro |

---

## 1. Inventory

`data/cves.json` contains every `High`/`Critical` stable CVE since
**2023-10-01** (three years): 1,199 rows. `data/rce_cves.json` filters them to
the 879 with an RCE path (or exploited in the wild), and
`data/rce_priority.json` keeps the 142 highest-priority ones (`Critical`
memory-safety plus all 20 exploited in the wild). The 7 CVEs from the last two
stable releases are the ones turned into runnable cases.

The severity that matters is Chromium's (`Critical` in the advisory). NVD
usually scores lower and later; for example CVE-2026-110922 is `Critical` for
Chrome and CVSS 8.8 (`HIGH`) in NVD. They are not contradictory: they measure
different things (potential impact inside the sandbox vs. a generic score).

## 2. Recovered patches (7/7)

| CVE | Bug | Repo | Commit | Topic |
|-----|-----|------|--------|-------|
| CVE-2026-110922 | 568719351 | chromium | `d50992ebe4` | `NavigationRequest` UAF in prerender checks |
| CVE-2026-113341 | 569165786 | skia | `02b14267cb` | Imagination FBO workaround in Ganesh |
| CVE-2026-113279 | 570093145 | chromium | `83ce9f18d7` | image maps in `AXObjectCacheImpl` |
| CVE-2026-113072 | 570638836 | chromium | `73dd2febfa` | pseudo-elements in LCP |
| CVE-2026-113280 | 570740320 | chromium | `3ab9f85874` | `FrameCaret::PaintCaret` and dirty layout |
| CVE-2026-113271 | 571618833 | chromium | `15248c94bc` | `title` reference in `AXNodeObject` |
| CVE-2026-113303 | 574041825 | chromium | `e193ceb7de` | unsynchronized `initialized_` in `WebRtcAudioDeviceImpl` |

Full diffs are in `patches/`. In 6 of 7 cases the commit includes the
regression test, which was used to derive the testcase.

## 3. Differential run

Command:

```bash
node harness/run-case.mjs --all
```

| CVE | Vulnerable (155.0.8059.84) | Patched (156.0.8078.47) | Verdict |
|-----|---------------------------|--------------------------|---------|
| CVE-2026-113072 | `entry.element` = `::before` | `entry.element` = `null` | **behavioral difference** |
| CVE-2026-113279 | 800 iterations, no crash | 800, no crash | no crash |
| CVE-2026-113271 | 700 iterations, no crash | 700, no crash | no crash |
| CVE-2026-113280 | 1500 frames, no crash | 1500, no crash | no crash |
| CVE-2026-113303 | 120 cycles, no crash | 120, no crash | no crash |
| CVE-2026-110922 | — | — | blocked (BFCache/SW sequence) |
| CVE-2026-113341 | — | — | not reproducible (Imagination driver) |

### CVE-2026-113072: the only observable difference

This is the strongest result in the lab. The same testcase, run against both
official builds, gives:

```json
// 155.0.8059.84 (vulnerable)
{"hasElement": true, "isTargetDiv": false, "tagName": "::before",
 "ctor": "Element", "parentTag": "DIV"}

// 156.0.8078.47 (patched)
{"hasElement": false, "isTargetDiv": false, "tagName": null,
 "ctor": null, "parentTag": null}
```

On 155 the LCP observer receives the pseudo-element; on 156
`Performance::CanExposeNode()` filters it out and `element` is `null`. This
proves the vulnerable path exists and that the patch cuts it. It does not by
itself prove memory corruption: that needs the observable state of stage 1
(shaping + live `gdb`) — see [`../docs/EXPLOITATION.md`](../docs/EXPLOITATION.md) §1.

### Remaining cases

The accessibility, caret and WebRTC cases do exercise the vulnerable path
(accessibility forced with `--force-renderer-accessibility`, fake audio device)
but **do not fault in release builds**. That is expected, and it is exactly
what the stage-1 techniques exist for:

- `StringImpl` UAF (113271) and AX object UAF (113279): the heap rarely
  collides by chance — reclaim the freed slot with a controlled object of the
  same size and watch the reentrant use in `gdb`.
- Layout reentrancy during paint (113280): break inside `PaintCaret()` on the
  patch's own sequence instead of waiting for natural timing.
- Audio thread race (113303): breakpoint the unsynchronized `initialized_`
  read and drive attach/teardown pairs; the window is then deterministic
  instead of random.

A "no crash" here **does not invalidate** the CVE; it only means passively
waiting for a fault is the wrong detection method. Next actions per case are
tracked in [`STAGES.md`](STAGES.md).

## 4. CVE-2026-110922: web-content reproducer (negative result)

A dedicated reproducer (`harness/repro-110922.mjs`) was built with an embedded
dynamic server: the static harness cannot stall a response, and the sequence
needs one.

```bash
node harness/repro-110922.mjs \
  --browser builds/155.0.8059.84/chrome-linux64/chrome \
  --attempts 2 --delays 0,25,100
```

Two harness blockers were found and removed first: Playwright disables BFCache
with `--disable-back-forward-cache`, and `Cache-Control: no-store` makes a
document BFCache-ineligible. After that the control run restores with
`persisted: true`.

### 4.1 DevTools disables prerendering entirely

Every Playwright-driven attempt reported `PrerenderFinalStatus` **69**, which
was initially read as "host reused". The enum carries explicit values, and 69
is `kPrerenderingDisabledByDevTools` (reuse is 88). The cause is in
`content/browser/devtools/devtools_instrumentation.cc`:

```cpp
bool IsPrerenderAllowed(FrameTree& frame_tree) {
  auto* render_frame_agent_host = ...;
  if (render_frame_agent_host &&
      render_frame_agent_host->HasSessionsWithoutTabTargetSupport()) {
    return false;   // -> kPrerenderingDisabledByDevTools
  }
  ...
}
```

A CDP session that does not advertise tab-target support (Playwright's tracing
session, or any raw `newCDPSession(page)`) makes Chromium silently reject every
speculation rule with status 69. On this build the request is only issued as
`Sec-Purpose: prefetch;prerender` and never becomes a prerender host. No
Playwright-driven run can reach the vulnerable preconditions, so the technique
in section 4.2 (launch the browser directly, let the page drive itself) is
mandatory for this CVE.

### 4.2 CDP-free self-driving harness

`harness/selfdrive-110922.mjs` launches Chromium with no debugging port. The
page registers the Service Worker, injects the speculation rules, updates the
worker and calls `history.back()` itself, reporting milestones with
`fetch()`/`sendBeacon()` to the local server.

```bash
node harness/selfdrive-110922.mjs --browser /usr/lib/chromium/chromium \
  --attempts 2 --delay 0 --count 2
```

Without DevTools prerendering really runs (both `?prerender=1` stalled and
`?prerender2` requested with `Sec-Purpose: prefetch;prerender`), and the run
reaches the full sequence:

```
pageshow(false) -> ready -> ready -> pagehide -> phase2 -> stalled -> bumped
  -> waiting -> backing -> sw2-activated -> pagehide -> phase1-replay
  -> pageshow(false)
```

The eviction window is still unreachable:

| Observation | Measurement |
|-------------|-------------|
| Service Worker v2 activation | ~900–1000 ms after `skipWaiting` |
| BFCache restore | completes in milliseconds |
| Pending prerender started at `back` | no new request in every run |
| `queued-load` beacon (prerender 2 committed) | never emitted |
| Final `pageshow` | `persisted=false` (restore was replaced) |
| Prerender 1 connection open at `back` | yes (`open=1`), so it is still the running host |
| Delay sweep 600–1200 ms | 0 crashes in 9 runs |

The order at `--delay 950` is the clearest measurement:

```
-954ms waiting -> +0ms backing -> +51ms sw2-activated
  -> +57ms pagehide(persisted=true) -> +69ms pageshow(persisted=false)
```

`history.back()` at `+0` starts the BFCache restore. The Service Worker
activation that evicts the entry lands at `+51 ms`, i.e. **57 ms after** the
restore began, as a separate task. It destroys the restore navigation and the
page reloads normally (`persisted=false`), but it cannot land inside
`BeginNavigation()`.

One caveat on the `?prerender2` request: it is issued right after the rule is
injected, with `Sec-Purpose: prefetch;prerender`, and the page's script never
runs (no `queued-load` beacon). The pending host is therefore prefetched while
it waits in `pending_prerenders_`; the early request is not proof that the host
started. Either way, cancelling prerender 1 at `back` does not produce a new
navigation start in the same stack.

**Result: 0 crashes in 30+ attempts across both drivers.** The bug is real, but
it is not reachable with controllable timing from web content on this build.
The regression test evicts synchronously from `DidStartNavigation`, which
content cannot schedule.

## 5. Release-build crashes with core + gdb (no sanitizers)

The lab's crash-analysis path is the ordinary binary-debugging path, documented
in [`docs/GDB.md`](../docs/GDB.md) — no sanitizer build is involved anywhere:

- the harness spawns the browser through `sh -c 'ulimit -c unlimited; exec "$@"'`
  with the profile as working directory and `--disable-breakpad`, so the kernel
  writes a core instead of Crashpad swallowing the signal;
- on a crash it runs `gdb -q -batch` over the core with `bt`, registers,
  `x/i $rip` and `info proc mappings`, writes the full output to
  `findings/raw/<CVE>.attemptN.core.txt` (or
  `findings/raw/<CVE>.<stage>.<label>.core.txt` when run through
  `run-case.mjs --cores`) and prints a digest;
- the core is deleted afterwards unless `--keep-core` is passed.

The release binary is stripped, so Chromium frames are addresses, but the
signal, faulting address, instruction and containing module are enough to
separate a browser-process `SIGSEGV` from an unrelated CHECK (`SIGABRT`).

The pipeline was validated end to end twice: first with a deliberately
crashing binary (the harness produced the core, resolved `#0 main () at
crashy.c:1`, reported `crash=true` and exited `42`), and now with a real
renderer core of the release build itself — `chrome://crash` under
`oracle.mjs --cores-dir` writes a kernel core that gdb reports as
`Program terminated with signal SIGSEGV`, faulting instruction
`movl $0x0,0x0`, plus registers and the module map. Two bugs were found and
fixed while wiring cores into `run-case.mjs --cores`:

1. `analyzeCore` passed the whole command list joined in a single `-ex`; gdb's
   parser aborted mid-script, so the report silently lacked `info registers`,
   `x/i $rip` and the module map. Each command is now its own `-ex`.
2. `findCore` could pick a stale core left by an earlier run and analyse it as
   this run's crash; cores are now filtered by run start time (older ones are
   preserved, never analysed).

Caveat: a UAF only faults when the freed slot is unmapped or reused as an
incompatible object. PartitionAlloc keeps it mapped, so a release build may not
crash even with a real UAF. That is why the lab does not wait for the fault:
the freed slot is reclaimed with a controlled object of the same size (stage-1
shaping), and the use is watched live — breakpoints on the lines the patch
changes, hardware watchpoints over the dangling slot. The C++ regression test
remains the deterministic reproduction and is breakpointed the same way.

## 6. Patch recovery for the in-the-wild backlog

Working newest-first through `data/rce_priority.json`, the fix commit was
recovered for the 5 most recent in-the-wild CVEs after the October 2026 cases:

| Advisory | CVE | Component | Root-cause commit | Repository |
|----------|-----|-----------|-------------------|------------|
| 2026-09-03 | CVE-2026-85046 | Type confusion in V8 | `e0562d87ad` | v8/v8 |
| 2026-03-31 | CVE-2026-5281 | UAF in Dawn (wire) | `3c890398bd` | google/dawn |
| 2026-03-13 | CVE-2026-3909 | OOB write in Skia | `0cab3e4ee3` | google/skia |
| 2026-03-12 | CVE-2026-3910 | Inappropriate impl. in V8 | `7076ba135f` | v8/v8 |
| 2026-02-13 | CVE-2026-2441 | UAF in CSS | `e045399a1e` | chromium |

Two retrieval problems had to be fixed in `scripts/find_fixes.py`:

1. **Autorolls.** For V8 and Dawn the chromium commit is only
   `Roll V8 from A to B` / `Roll Dawn from A to B`, which carries no
   root-cause diff. The script now parses the roll, walks the submodule range
   on `*.googlesource.com`, and selects the commit that references the bug.
   `CVE-2026-85046` is the clearest case: the chromium search returns a later
   roll containing only a *test-flake* fix, while the actual fix
   (`e0562d87ad`, "Don't inline Array.prototype.sort on mixed elements kinds")
   landed three weeks earlier and was found through the submodule history.
2. **Test-bundle commits.** V8 occasionally moves old regression tests into
   the public repo in one commit listing dozens of bugs. It matches the search
   but is not the fix, so candidates are now scored by `Fixed:`/`Bug:` lines
   and penalised when they mention many bugs or move tests.

The submodule searches also work without a roll hit: `CVE-2026-3910` was found
directly in `v8/v8` (`7076ba135f`, "[maglev] disable Phi untagging").

## 7. First RCE-ladder case: CVE-2026-85046 (stages 1–2 done)

Builds fetched with the new parallel mode
(`scripts/fetch_chrome.py --connections 16`, added because a single stream
was capped at ~60 KB/s on this link): vulnerable `152.0.7977.75` (last build
before the fix) vs patched `152.0.7977.82`.

### Stage 1 — behavioral differential (the upstream assertion, page-style)

| Build | `JSON.stringify(bad)` | `bad.join("~")` |
|-------|----------------------|-----------------|
| 152.0.7977.75 (vulnerable) | `[8595714,8595770]` | `8595714~8595770` |
| 152.0.7977.82 (fixed) | `[{},{}]` | `[object Object]~[object Object]` |

Verdict: **`behavioral-difference`**. The trigger is the patch's own
`regress-crbug-542403045.js` (mid-tier forced with natives syntax declared in
`case.json -> flags`, exactly as the mjsunit test declares its flags).
`%HasSmiElements(bad) && bad[0] === object` — the upstream assertion — was
verified `true` on the vulnerable build and `false` on the patched one
(`diag3.html`: 3 runs × 3 attempts, 100% deterministic).

### Stage 2 — leak (addrof)

`poc-leak.html` (`--stage leak`): vulnerable `level: "leak (addrof: object ->
compressed pointer as integer)"`, patched `level: "none"`.

| Signal | Vulnerable | Fixed |
|--------|-----------|-------|
| numeric values leaked | 10 | 0 |
| all in compression-cage integer range | true | false |
| same object → same value across independent triggers | true (`8576308`) | false |
| different object → different value | true | false |
| neighbour pair byte delta | **16 B** (one object size) | null |

The neighbour-pair check is the address-granularity corroboration: two fresh
adjacent objects decode to integers 8 apart = 16 bytes at `ptr >> 1` encoding
— non-address data does not land on that structure. Accepted in-band as the
corroboration step of `docs/EXPLOITATION.md` §2 (recorded as a methodology
amendment: gdb eyeballing is no longer the only accepted form).

### Methodology findings (worth keeping)

1. **Natural tier-up gap.** The page's natural warmup (70k–100k calls,
   `diag4-trace.html`) does **not** reach the confused inlining state, while
   the upstream force recipe does so deterministically. A no-flag,
   web-realistic trigger is an open item — solve before claiming a
   weaponizable PoC; record the warmup/tiering conditions that reach it.
2. **Plain-JS discriminators for elements-kind confusion.** `%HasSmiElements`
   is natives-only; `JSON.stringify`/`Array#join` are Smi-specialized
   consumers and decode confused pointers as numbers. Found by differential
   probing (`diag5.html`), not by reasoning about IC stubs.
3. **Renderer V8 output is not reachable from the harness** (`--trace-opt`,
   `%DebugPrint`): Playwright does not capture renderer stderr headless.
   Options recorded in the case README (direct gdb launch, logging flags).
4. Two harness bugs were fixed earlier today and matter for every stage:
   `analyzeCore`'s joined `-ex` (registers/`x/i`/module map were silently
   dropped) and stale-core misattribution (`findCore` mtime filter).

## 8. Limitations and next steps

The next steps follow the three-stage scope
([`../docs/EXPLOITATION.md`](../docs/EXPLOITATION.md), tracker:
[`STAGES.md`](STAGES.md)). No sanitizer build is part of the plan.

1. **Stage 1 on the four stress cases (113271/113279/113280/113303).** Stop
   iterating and start shaping: reclaim the freed object with a controlled one
   of the same size, breakpoint the exact lines the fix changes, watch the
   dangling slot. Evidence target: differential crash or a recorded live
   observation of the corrupted state.
2. **CVE-2026-113072** already produced stage-2 evidence (exposure of a node
   the API must not return). Decide whether it can carry address-like data; if
   not, it closes at exposure level as a regression test.
3. **CVE-2026-110922.** Web content now reaches every step except the
   synchronous eviction: the stalled host is alive at `back`, the restore is
   evicted ~57 ms later by SW activation, and the delay sweep (600–1200 ms)
   does not move the eviction into `BeginNavigation()`. Remaining option: the
   patch's own `content_browsertests` regression test on a debug build
   (`--gtest_filter='*EvictBackForwardCacheDuringPrerenderActivationCheck*'`),
   breakpointed with gdb in `NavigationRequest::BeginNavigation`, or a
   browser-process debugger breakpoint in `DidStartNavigation`. Do not retry
   through Playwright: CDP without tab-target support disables prerendering
   (status 69).
4. **CVE-2026-85046 — stage 3 recon complete, fakeobj blocked (honest
   ceiling: rungs 1–3).** Stages 1–2 are done (this document, §7): the
   trigger reproduces the upstream assertion differentially and the confusion
   yields an addrof corroborated at address granularity. Stage-3 recon
   (`diag6`–`diag9` in the case directory) eliminated four fakeobj sources
   with evidence: object-stores heal the array; major-GC reclaim fails
   because marking follows odd slots (WeakRef model M1, 360k plants, 0
   aliases); the missing-write-barrier/minor-GC window does not open in the
   reachable shapes; the double-elements union is pre-rejected by the patch's
   own bailout. Remaining candidates: refined WB timing (young content in old
   elements at copy-back with the store buffer flushed) and JIT-schedule
   stores under mismatched feedback; plus the standing no-flag trigger and
   renderer-stderr (`%DebugPrint`) items from §7.
5. **CVE-2026-113341.** Without an Imagination GPU there is no possible
   reproduction. The value is in analyzing the workaround and comparing it with
   `GLES2DecoderImpl`.
6. **False negatives.** Race cases run a limited number of iterations.
   More `iterations` in parallel helps, but it is not the tool of choice: a
   breakpoint on the racy read/write makes the window deterministic on the
   first hit.
