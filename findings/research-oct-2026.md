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
