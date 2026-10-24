# Lab results

Date: 2026-10-24
Builds used:

| Role | Version | Source |
|------|---------|--------|
| Affected (6 CVEs from Oct 20) | 155.0.8059.84 | Chrome for Testing |
| First patched | 156.0.8078.47 | Chrome for Testing |
| Affected (CVE-2026-110922) | 155.0.8059.79 | Chrome for Testing |
| System Chromium (initial checks) | 155.0.8059.39 | distro |

---

## 1. Inventory

`data/cves.json` contains **34 `Critical` CVEs** published between 2026-08-24
and 2026-10-20. The 7 most recent ones (last two stable releases) are the ones
turned into runnable cases.

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
itself prove memory corruption: that requires ASAN.

### Remaining cases

The accessibility, caret and WebRTC cases do exercise the vulnerable path
(accessibility forced with `--force-renderer-accessibility`, fake audio device)
but **do not abort in release builds**. That is expected:

- `StringImpl` UAF (113271) and AX object UAF (113279): the heap rarely
  collides without ASAN.
- Layout reentrancy during paint (113280): requires DCHECK/ASAN or exact timing.
- Audio thread race (113303): needs a real audio backend and TSAN.

A "no crash" here **does not invalidate** the CVE; it only means the detection
environment is too weak.

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

The eviction window is still unreachable:

| Observation | Measurement |
|-------------|-------------|
| Service Worker v2 activation | ~900–1000 ms after `history.back()` |
| BFCache restore | completes in milliseconds |
| Pending prerender started at `back` | `startedAtBack=false` in every run |
| Prerender 2..6 requests | all issued ~2 s before `back` |

In this build the speculation-rules path starts every requested prerender
instead of keeping the surplus in `pending_prerenders_`, so cancelling prerender
1 does not synchronously start a queued one. The eviction therefore always lands
before the restore (normal reload) or long after it (`persisted: true`), never
inside `BeginNavigation()`.

**Result: 0 crashes in 9+ attempts.** The bug is real, but it is not reachable
with controllable timing from web content on this build. The regression test
evicts synchronously from `DidStartNavigation`, which content cannot schedule.

## 5. Limitations and next steps

1. **ASAN build.** It is the next step with the best cost/benefit ratio.
   `docs/ASAN.md` describes how to build with `is_asan=true`. With ASAN, cases
   113271/113279/113280/113303 are much more likely to report the
   use-after-free.
2. **CVE-2026-110922.** Requires a server that stalls responses, Speculation
   Rules and Service Worker activation. The patch's test can be adapted into a
   browser test (`content_unittests`) instead of trying it from plain HTML.
3. **CVE-2026-113341.** Without an Imagination GPU there is no possible
   reproduction. The value is in analyzing the workaround and comparing it with
   `GLES2DecoderImpl`.
4. **False negatives.** Race cases run a limited number of iterations.
   Increasing `iterations` and running in parallel improves the detection rate
   but does not guarantee it.
