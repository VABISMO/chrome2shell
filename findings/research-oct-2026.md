# October 2026 CVEs — research log (no public PoCs)

Status date: 2026-10-26. Scope: CVE-2026-113279, 113280, 113271, 113303
(113072 closed earlier; 113341 requires an Imagination GPU — out of lab scope).

Build matrix (local): 145.0.7632.67, 146.0.7680.72/.76, 152.0.7977.75/.82,
155.0.8059.84, 156.0.8078.47. Verified with binary strings:
**156.0.8078.47 already contains the 113280 fix**
(`FrameCaretSkipHiddenCheck` feature string present) → newest vulnerable
build for 113280 is **155.0.8059.84**; 156 serves as the fixed differential.

New tooling added this session:

- `harness/ax-run.mjs` — direct-run + a live AX client: loops
  `Accessibility.getFullAXTree` over CDP while the page churns. AX bugs need
  an active client pulling the tree; a page alone never opens the window.
- `harness/axprobe.mjs` — pulls the AX tree of a page and prints
  image/map/area-related nodes with parent chains (verifies preconditions
  live instead of guessing).
- Both drivers take `LAB_PROFILE_DIR` (default /tmp/opencode) so profiles and
  reports avoid a full /tmp tmpfs.

## CVE-2026-113279 (AX image-map removal, bug 570093145)

Patch: `patches/CVE-2026-113279.patch`. Vulnerable source verified against
chromium `155.0.8059.84` (raw fetch of `ax_object_cache_impl.cc`):

- `RemoveSubtreeInternal`'s `<map>` branch calls
  `NotifyParentChildrenChanged(image_ax_object)` unconditionally; the patch
  gates it off during `AXObjectCacheLifecycle::kProcessDeferredUpdates`.
- `GetAXImageForMap(map)` requires: a DOM child of `<map>` (the `<area>`)
  has an AXObject whose parent is the image AXObject, not yet detached.
  **DOM order matters**: `<map>` must precede `<img>` inside a removed
  subtree, or the image is already detached when the map branch runs.
- axprobe verified the live precondition: the AX tree contains
  `image → link` (area parented to image) for `<img usemap>+<map><area>`.

Tried (build 155, ax-run, 120–310 tree pulls per run):
- wrapper/img/map removal with 250ms beats (structure alive ≥1 pull), map-first
  ordering — clean.
- 12-operation sweep (map.remove, img.remove, wrapper.remove, display
  toggle/show, usemap-change, name-change, area-remove, innerHTML-clear,
  src-change, map-then-img, replace-children), 12 reps each, fresh structure
  per rep — **all 144 mutations clean, no crash**.

Next: the crash needs the removal processed *inside* an in-flight deferred
pass (interleaved with a serialization), e.g. queue a removal while a pull is
mid-serialization (nested message pump) or combine with
`in_cached_attribute_values_update_` re-entry (the sibling guard for
crbug.com/436609528 shows that re-entry class exists). Plan: many maps
removed in one burst while pulls run at 20–50ms intervals (fill the queue so
processing spans a pull), plus `<select>`/popup document interplay.

## CVE-2026-113280 (FrameCaret::PaintCaret re-entry, bug 570740320)

Patch: `patches/CVE-2026-113280.patch`. Bug: `PaintCaret` calls
`IsHidden()` → `SelectionHasFocus()` → synchronous
`UpdateStyleAndLayout()`; reached during `PrePaintTreeWalk` via an SVG
feImage filter painting a subtree with a caret → physical fragments rebuilt
while being iterated → UAF. Unit test in the patch: contenteditable + focus
+ collapsed caret + pending layout at paint time.

Verified live (screenshot): feImage with in-document `href="#frag"` DOES
render in 145/155 — but the filter REPLACES the subtree's paint, so the caret
never paints unless the filter composites `SourceGraphic`.

Tried (builds 145 and 155, direct-run): 4 editables (caret cycled through
them: filtered ancestor, foreignObject in filtered svg, filter directly on
the editable, caret inside feImage-referenced fragment), feComposite with
SourceGraphic, will-change:filter, 400 layout-dirtying beats per run — clean.

Next: verify with the fixed build (156) differential whether our pages even
reach PaintCaret-during-PrePaint (add a JS-observable layout-forced
side-effect probe), then vary the filter placement (filter on the SVG root
containing the editable via foreignObject; `<use>` + filter; caret in an
iframe inside the filtered subtree).

## CVE-2026-113271 (dangling AtomicString& into attribute storage, bug 571618833)

Patch: `patches/CVE-2026-113271.patch`. `Description()` held a
`const AtomicString&` from `FastGetAttribute(kTitleAttr)` across
`GetInnerTextWithoutUpdate()`/`TextAlternativeFromTitleAttribute`, which can
reallocate the SAME element's attribute storage → dangling reference.

Tried (builds 145/155 with ax-run pulling names/descriptions): titled
containers with lazy `<img loading=lazy>` (src assignment during layout =
known synchronous attribute writer), custom element with attributeChangedCallback
churn, `<picture>/<source>`, attribute realloc churn + viewport scrolling —
title intact every run, no crash.

Next: identify what writes the TITLE element's OWN attributes during its
name computation. Strongest untested candidate: making the titled element
itself the lazy-loadable/replaced element (e.g. `<img loading=lazy title=…>`
where the name-from-contents path forces layout inside
`TextAlternativeFromTitleAttribute`), and form controls / `<slot>` +
shadow-DOM slot-reassignment (the same mutation-during-traversal class as
the closed CVE-2026-113072).

## CVE-2026-113303 (WebRtcAudioDeviceImpl UAF, bug 574041825)

Patch: `patches/CVE-2026-113303.patch` (includes unit tests with the exact
race: `SetAudioRenderer` releases `lock_` to run
`WebRtcAudioRenderer::Initialize()` while the signaling thread runs
`Terminate()`; the renderer keeps a raw `source_` to the terminated device).

Web translation plan (not yet implemented): two RTCPeerConnections in one
page (loopback with audio), remote audio playing (attaches the WebRTC audio
renderer), then rapid track-stop/close cycles to interleave `Terminate()`
with `SetAudioRenderer()`; run under `--use-fake-device-for-media-stream`
with audio. Race is thread-interleaved → probabilistic; needs many iterations
and a crash-pair harness (stderr signal + last beacon phase).

## Reproducing the drivers

```
export LAB_PROFILE_DIR=$HOME/.cache/cvelab-profiles
node harness/ax-run.mjs cases/CVE-2026-113279/map-remove-ax.html \
  --browser builds/155.0.8059.84/chrome-linux64/chrome --timeout 150000 \
  --out ~/.cache/cvelab-runs/sweep.json --stderr ~/.cache/cvelab-runs/sweep.err
node harness/axprobe.mjs /tmp/mapstatic.html   # inspect AX tree preconditions
```

## Tooling note: local d8 cannot reproduce CVE-2026-3910 stage-0 (2026-10-27)

`/home/cryptocalypse/v8dbg/src/out.debug26/d8` is built from V8 checkout
`041a33f6` (2026-03-10) whose `MaglevGraphBuilder::CanElideWriteBarrier` is
already refactored with the post-fix guard shape
(`RecordSmiUseIfNeeded` / `uses_require_smi()`); the fix commit `7076ba135`
(from `patches/CVE-2026-3910.patch`) is not even in that repo's history.
Evidence (clobber discriminator `/tmp/opencode/uaf-discrim.js` sequence):
after `major_gc; trigger(0x10000000); minor_gc` the field `o.x` survives
4000 string allocations, 1000 double arrays and a full `major_gc` without
type change or fault — the pointer is live, no UAF. Maglev itself works
(`%GetOptimizationStatus` = 25). Consequence: deterministic rung-6 payload
validation must run in the **browser 146.0.7680.72** (V8 14.6.202.11), which
is proven vulnerable (rung-5 landing). `cases/CVE-2026-3910/d8/rung6-validate.js`
is kept as the payload-logic harness for a future pre-fix d8 build
(build at `git checkout 7076ba135~1` in a full V8 clone, then it applies).

## Microscope verdicts — CDP tracing (2026-10-27)

Tool: `harness/ax-run.mjs --trace-cats "<cats>"` (CDP Tracing domain;
**Tracing.end must run explicitly — dataCollected flushes only at end**).

- **CVE-2026-113279**: under the burst/sweep triggers the AX lifecycle runs
  for real: `ProcessDeferredUpdatesLifecycleStage` ×46,
  `SerializeLifecycleStage` ×46, `FinalizingTreeLifecycleStage` ×44 per run.
  The vulnerable function's phase IS exercised; the crash-shaped interleave
  (removal mid-traversal with a live map AXObject whose area children are
  destroyed by `ChildrenChangedWithCleanLayout(image)`) still does not fire
  in release shapes tested. Next: force a `<map>` AXObject into the tree
  (aria-label/role) so `RemoveSubtreeInternal` runs the map branch with
  `object != null`, and interleave removals INSIDE a single deferred pass
  (already the burst cadence — combine with the forced map object).
- **CVE-2026-113280**: ZERO `Paint`-or-`Layout`-inside-`PrePaint` nesting in
  builds 145, 146, 152 and 155 across all page variants (filtered ancestor,
  foreignObject, filter-on-editable, will-change, iframe) — the commit's
  "feImage filter painting during PrePaintTreeWalk" context is never reached.
  Either a narrower page condition is required (candidate: SVG-root filter
  with external feImage href) or the pipeline landed between 155 and the
  pre-156 fix window. Trace-evidence over guesses: any future variant must
  first show non-zero nesting before burning crash-hunt runs.

### CVE-2026-113279 — round 2 (2026-10-27): serializer as the crash sink + 5 new families

Structural finding (source): `AXObjectCacheImpl::EnsureSerializer()` ALWAYS
constructs the renderer `AXTreeSerializer` with **`crash_on_error = true`** —
so any cache-vs-serializer inconsistency is a RELEASE crash, chiefly
`GetClientTreeNodeParent()` → `NOTREACHED()` (crash key
`ax_ts_missing_parent_err`) when an update's parent id is no longer in the
client tree, plus `CHECK(lca)`/`CHECK(child)` in `ComputeReparentingLCA`.
Also mapped: `AXObjectCacheLifecycle` semantics (`StateAllowsImmediateTreeUpdates`
= kProcessDeferredUpdates|kFinalizingTree; `ChildrenChanged()` has an
always-on `CHECK(StateAllowsDeferTreeUpdates())`), and the `in_cached_attribute_values_update_`
guard window.

Families executed today on 155 with live AX client (--ax-interval 50) +
tracing, all clean (no signal/CHECK/NOTREACHED):
1. `deferred-entry.html` — 600 ops over every RemoveSubtree entry vector
   (restore-prune via display, role-change, subtree-attach, direct removals).
2. `finalizing-nest.html` — role=button+title forced layout during AX pass with
   display churn destroying the LayoutImage (nested ObjectDetached→RemoveSubtree(map,false)).
3. `immediate-mode.html` — removals + focus/selection in the same task
   (IsImmediateProcessingRequired → immediate serialization triggers).
4. `queue-dangle.html` — area href/coords churn (AXObject-valued queue entries)
   + same-tick wrapper removal (map-branch rebuild in the same deferred pass).
5. `multi-primary.html` — 3 imgs sharing one usemap, primary destroyed/rebuilt
   (168 rebuilds), usemap flips, primary-switch ClearChildren.

State: mechanism fully mapped; the missing interleaving likely needs the
restricted bug report's original repro or a client pattern our CDP client does
not reproduce. Next-if-continued: browser-side event patterns
(BrowserAccessibilityManager CHECKs), or debug-build CHECK reproduction.

### CVE-2026-113303 — source-traced web recipe (2026-10-27)

Full chain traced (files: `media_stream_renderer_factory.cc`,
`webrtc_audio_device_impl.{h,cc}`, webrtc core ADM interface):
- **Attach side**: a REMOTE PC audio track consumed via `<audio srcObject>`
  invokes `MediaStreamRendererFactory` → `SetAudioRenderer` (main thread):
  release `lock_` → `renderer->Initialize(this)` (THE window) → relock.
  `pc.ontrack` alone never attaches — earlier loops were missing this.
- **Terminate side**: `WebRtcAudioDeviceImpl::Terminate()` asserts the
  SIGNALLING thread and runs at webrtc-core PC teardown (`pc.close()`), moving
  `renderer_` out and DisconnectSource().
- **Dangling use**: renderer keeps raw `source_` to the terminated device
  (vulnerable), freed at window/device destruction → teardown navigation is
  the deref moment.
- Constraints learned: **500 RTCPeerConnections = lifetime cap per renderer
  process** (probe `pccap-probe.html` nails exactly 500 create+close) →
  ≤245 cycles/run, volume = batched runs.

`webrtc-audio-race-v4.html` validated: 240 attaches / 239 srcObject sets /
237 closes per run, teardown navigation executes. Batch runs hunt the crash.
