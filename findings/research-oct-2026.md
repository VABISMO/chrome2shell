# October 2026 CVEs — research reference

Scope: CVE-2026-113279, CVE-2026-113280, CVE-2026-113271, CVE-2026-113303.
No public PoCs exist for these; everything below is derived from the recovered
patches (`patches/CVE-2026-113*.patch`) and, where noted, from the vulnerable
sources fetched at the affected tag. CVE-2026-113072 is closed at exposure
level and CVE-2026-113341 requires Imagination GPU hardware.

Builds: vulnerable `155.0.8059.84`, first patched `156.0.8078.47`.
`156.0.8078.47` already contains the 113280 fix (binary string
`FrameCaretSkipHiddenCheck`), which also makes 155 the newest vulnerable build
for that case.

## Tooling

- `harness/ax-run.mjs <page> --browser <build> [--ax-interval ms] [--trace-cats cats] [--watch-names prefix]`
  — direct-run plus a live accessibility client (`Accessibility.getFullAXTree`
  loop over CDP), optional Chrome tracing (`Tracing.end` is driven explicitly —
  `Tracing.dataCollected` only flushes there) and an AX name-stability watcher.
- `harness/axprobe.mjs <page>` — one-shot full AX-tree dump (roles/names/parents)
  to verify trigger preconditions.
- `--enable-logging=stderr --v=1` exposes webrtc `RTC_LOG`/`SendLogMessage`
  lines (`WRADI::`, `MSRF::`, `WRAR::`, `WebRtcVoiceEngine::Init/Terminate`) —
  the lifecycle microscope used for 113303.

---

## CVE-2026-113303 — WebRtcAudioDeviceImpl attach to terminated device

**Status: 🟡 vulnerable state reached and differentially proven (stage 1 by
behavior); crash phase in progress.**

Mechanism (patch `e193ceb7de`, source-traced at the affected tag):

- `SetAudioRenderer` (main thread) releases `lock_` around
  `renderer->Initialize(this)` — the unprotected window.
- `Terminate()` (signalling thread) moves `renderer_` out and disconnects the
  source; it runs mid-session via the chain
  `ConnectionContext::ReleaseMediaEngine` (last `MediaEngineReference` dropped)
  → `WebRtcVoiceEngine::Terminate` → `adm()->Terminate()`.
- Each `webrtc::PeerConnection` holds that RAII reference **until the object is
  destroyed — `pc.close()` is not enough**; destruction needs the JS wrapper
  collected (major-GC churn) plus ~3s for async transport teardown.
- Vulnerable: no `initialized_` gate → an attach after `Terminate` is accepted
  and keeps a raw `source_`; the next `Terminate` early-returns and never
  disconnects it. Fixed: `if (!initialized_ || renderer_) return false`, plus a
  post-window recheck that disconnects/tears down a renderer if `Terminate`
  raced the window.

Evidence (`findings/raw/CVE-2026-113303.differential.v15.json`):

| Build | Attach after Terminate | Sink |
|-------|------------------------|------|
| 155.0.8059.84 (vulnerable) | **accepted** (8–10/10 cycles, `SetAudioRenderer` + `sink device_status=OK`) | live |
| 156.0.8078.47 (fixed) | **rejected** (`WRADI::SetAudioRenderer failed`, all cycles) | none |

Audio pulls are confirmed by trace: `WebRtcAudioRenderer::Render` /
`SourceCallback` / `WebRtcAudioDeviceImpl::RenderData` all fire (~986/cycle-set)
after the holder is killed — the dangling deref site executes.

Case files (`cases/CVE-2026-113303/`):

- `webrtc-audio-race-v13.html` — single-window differential recipe
  (gUM → loopback pair → attach#1 → stop mic + close PCs + drop refs +
  major-GC + 3.2s → engine Terminate → attach#2).
- `webrtc-audio-race-v17.html` + `v17-holder.html` — cross-window recipe
  (holder A terminates its engine in place; B attaches to A's terminated
  device, then A is killed; PartitionAlloc spray armed for slot reuse);
  `v11-dead.html` is the static same-origin kill target.
- `testcase.html` — original stress entry (`case.json`).

Remaining leg: **the device never frees mid-run** (device dtor never logged in
any variant — candidate holders: cross-realm refs in the consumer window,
session-history retention of popup documents, the webrtc factory's
`scoped_refptr adm`). Since reads of freed-but-mapped memory are silent, the
crash also needs the freed slot to be reused (spray included in v17).

Next action: break the retention (evict/close popups only after the consumer
holds no A-realm objects; or structured-transfer everything out of A) → watch
the device dtor count rise → pull-after-free window → crash differential
(155 faults, 156 clean).

---

## CVE-2026-113279 — AXObjectCacheImpl image-map removal

**Status: 🧪 mechanism fully mapped; no crash-yet shape.**

Mechanism (patch `83ce9f18d7`, vulnerable source at tag):

- `RemoveSubtreeInternal`'s `<map>` branch calls
  `NotifyParentChildrenChanged(image)` unconditionally; the patch gates it for
  `kProcessDeferredUpdates`.
- `GetAXImageForMap` needs an `<area>` AXObject whose parent is the (not yet
  detached) image — verified live with `axprobe`: the AX tree contains
  `image → link`.
- Lifecycle facts: `StateAllowsImmediateTreeUpdates` =
  `kProcessDeferredUpdates | kFinalizingTree`; `ChildrenChanged()` carries an
  always-on `CHECK(StateAllowsDeferTreeUpdates())`.
- The renderer's `AXTreeSerializer` is built with **`crash_on_error = true`** —
  any cache-vs-client inconsistency (missing parent id → `NOTREACHED`,
  `CHECK(lca)`) is a release crash; this is the intended crash sink.

Evidence: the deferred machinery runs under the triggers (trace:
`ProcessDeferredUpdatesLifecycleStage` ×46/run) but no shape has produced a
fault or a11y state divergence (155 vs 156 final trees identical after 600
mutations).

Case files: `multi-primary.html` (current trigger: three images sharing one
`usemap`, primary destroyed/rebuilt, usemap flips — exercises
`ObjectDetached → RemoveSubtree(map,false)` and primary-switch `ClearChildren`),
`testcase.html`.

Tested families (all clean in release): direct map/wrapper removal with live
AX client, 12-operation display/role/attr sweep, burst removals, forced-layout
nesting inside the name computation, focus/selection immediate-mode, AXObject-
valued queue dangle, aria-labelled map, multi-primary. Not yet tried: browser-
side event patterns and debug-build CHECK reproduction.

Next action: force a queue entry whose parent id the serializer has already
dropped (burst removals racing `getFullAXTree` at 20–50 ms), or reproduce the
checks on a debug build (`docs/EXPLOITATION.md` §1).

---

## CVE-2026-113271 — dangling `AtomicString` in AX name/description

**Status: 🧪 window identified; the attribute-storage writer is not yet
identified.**

Mechanism (patch `15248c94bc`):

- `AXNodeObject::Description`/`TextAlternativeFromTitleAttribute` hold
  `const AtomicString& title = FastGetAttribute(kTitleAttr)` (a reference into
  the element's own attribute array) across `GetInnerTextWithoutUpdate()`,
  which can reallocate that storage → UAF read of the title String.
- `GetInnerTextWithoutUpdate` → `ElementInnerTextCollector::RunOn`
  (`core/editing/element_inner_text.cc`) reads computed style; layout
  invalid at entry is tolerated (its clean-layout DCHECK is commented out) —
  so a forced layout inside the window is possible.
- Name fallback fact: `alt=""` **suppresses** the title fallback (HTML-AAM) —
  the titled element must have no `alt` for the title to be used.

Evidence: title→name confirmed live via `axprobe`; AX name/description
stability watcher (`--watch-names`) reports no anomalies in the runs so far.

Case files: `lazy-title-race.html` (titled lazy images, rAF scroll + per-frame
layout dirtying + 50 ms AX pulls), `testcase.html`.

Next action: identify what writes the **titled element's own** attribute array
during the window (adding an attribute reallocates; replacing does not) —
strongest untested candidates: title on a replaced/lazy element whose own
attributes are written by Blink during forced layout, and slot-reassignment
mutating `slot` attributes (same traversal-mutation class as the closed
CVE-2026-113072).

---

## CVE-2026-113280 — FrameCaret::PaintCaret layout re-entry

**Status: 🧪 gated — the crash context does not exist in any local build.**

Mechanism (patch `3ab9f85874`): `PaintCaret` → `IsHidden()` →
`SelectionHasFocus()` → synchronous `UpdateStyleAndLayout()`; reached during
`PrePaintTreeWalk` (commit example: an SVG feImage filter painting a subtree
with a caret) → physical fragments rebuilt while iterated → UAF.

Gate (trace evidence): across builds 145/146/152/155 and all page variants,
**zero `Layout`/`Paint` events nest inside `PrePaint`** — the commit's context
never occurs locally. feImage with in-document `href` renders (screenshot-
verified), and the filter must composite `SourceGraphic` or the caret never
paints.

Case files: `caret-feimage.html` (current variant), `testcase.html`.

Next action: any future variant must first show non-zero PrePaint nesting in a
trace before spending crash-hunt runs; remaining untested condition is a
narrower page shape (caret inside an iframe in the filtered subtree was tried;
SVG-root filter with external feImage href was not).

### 113303 — lifetime-leg findings (freed=1 experiment)

- Code queued after `location.replace()` dies at the navigation commit
  (~100–300 ms): a post-nav release/beacon never executes — release code must
  run in the same tick BEFORE the replace, or in a second window.
- The default nav recipe completed **271 cycles in one 15-min run with ZERO
  device dtors** (`WRADI::WebRtcAudioDeviceImpl()` count == `VEi` count == 271
  exactly, 541 post-Terminate attaches accepted, VET×270): the per-load device
  is created but never destroyed during the session — the retention survives
  self-navigation with no external JS references, i.e. it sits at the webrtc
  factory / process level (the `CleanupPeerConnectionFactory` signalling-hop
  path has no callers in the fetched sources; the factory's `scoped_refptr adm`
  likely keeps every device alive to shutdown).
- Consequence: a device-freed-while-sink-pulls window was not reachable by any
  navigation/GC shape tested (self-nav x271, popup kill, cross-window, ref
  release). Combined with the fix's own comments (locks over `initialized_`,
  DCHECK moves to locked regions), the fix reads primarily as **thread-safety
  hardening of a cross-thread state**; the release-build crash manifestation is
  rare/absent at 46k+ tick scale.
- The lab's stage-1 alternative for such bugs (`docs/EXPLOITATION.md` §1:
  "live observation of corrupted state") is satisfied by the **behavioral
  differential already banked** (`CVE-2026-113303.differential.v15.json`):
  vulnerable build accepts attach-after-Terminate (raw `source_` on a
  terminated device), fixed build rejects — same recipe, both builds.
