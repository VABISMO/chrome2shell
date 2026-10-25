#!/usr/bin/env node
/**
 * Runs a case against the vulnerable build and the patched one, then compares.
 *
 * Every case is stage-aware (`docs/EXPLOITATION.md`): stage 1 is the
 * crash/behaviour trigger, stage 2 the leak PoC, stage 3 the RCE PoC. The
 * entry file for the stage comes from `case.json -> stages.<stage>.entry`.
 *
 * Usage:
 *   node harness/run-case.mjs CVE-2026-113072
 *   node harness/run-case.mjs CVE-2026-113072 --stage leak
 *   node harness/run-case.mjs CVE-2026-113072 --stage rce
 *   node harness/run-case.mjs --all
 *   node harness/run-case.mjs CVE-2026-113280 --cores --keep-core
 *   node harness/run-case.mjs CVE-2026-113280 --headed
 */
import { createServer } from "node:http";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { extname, join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const STAGES = ["crash", "leak", "rce"];
const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json",
  ".css": "text/css; charset=utf-8",
  ".wasm": "application/wasm",
  ".png": "image/png",
  ".svg": "image/svg+xml",
};

function parseArgs(argv) {
  const out = {
    cases: [],
    all: false,
    headed: false,
    stage: "crash",
    cores: false,
    keepCore: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--all") out.all = true;
    else if (a === "--headed") out.headed = true;
    else if (a === "--cores") out.cores = true;
    else if (a === "--keep-core") {
      out.keepCore = true;
      out.cores = true;
    } else if (a === "--stage") {
      out.stage = argv[++i];
      if (!STAGES.includes(out.stage)) {
        console.error(`--stage must be one of: ${STAGES.join(", ")}`);
        process.exit(2);
      }
    } else if (a === "--vuln") out.vuln = argv[++i];
    else if (a === "--fixed") out.fixed = argv[++i];
    else out.cases.push(a);
  }
  return out;
}

async function startServer() {
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    let file = join(ROOT, decodeURIComponent(url.pathname));
    if (!file.startsWith(ROOT)) {
      res.writeHead(403).end("forbidden");
      return;
    }
    try {
      const body = await readFile(file);
      res.writeHead(200, {
        "Content-Type": MIME[extname(file)] ?? "application/octet-stream",
        "Cache-Control": "no-store",
        "Service-Worker-Allowed": "/",
      });
      res.end(body);
    } catch {
      res.writeHead(404).end("not found");
    }
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { server, port: server.address().port };
}

function runOracle({ browser, url, timeout, iterations, flags, headed, out, cores }) {
  const argv = [
    "harness/oracle.mjs",
    "--browser", browser,
    "--url", url,
    "--timeout", String(timeout),
    "--iterations", String(iterations),
    "--flags", flags.join(","),
    "--out", out,
  ];
  if (headed) argv.push("--headed", "true");
  if (cores) {
    argv.push(
      "--cores-dir", cores.dir,
      "--core-out", cores.coreOut,
      "--keep-core", String(cores.keep),
    );
  }
  return new Promise((resolvePromise) => {
    // With cores the whole tree must inherit `ulimit -c unlimited`, so the
    // oracle itself is re-exec'ed through sh (docs/GDB.md §2).
    const child = cores
      ? spawn(
          "sh",
          ["-c", 'ulimit -c unlimited 2>/dev/null || true; exec "$@"', "sh", process.execPath, ...argv],
          { cwd: ROOT },
        )
      : spawn(process.execPath, argv, { cwd: ROOT });
    let stderr = "";
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (code) => resolvePromise({ code, stderr }));
  });
}

async function loadCase(id) {
  const dir = join(ROOT, "cases", id);
  const meta = JSON.parse(await readFile(join(dir, "case.json"), "utf8"));
  return { id, dir, meta };
}

function browserFor(versionOrPath, override) {
  if (override) return override;
  // allow absolute paths (custom build, ASAN, system chromium)
  if (versionOrPath && versionOrPath.startsWith("/")) {
    return existsSync(versionOrPath) ? versionOrPath : null;
  }
  const p = join(ROOT, "builds", versionOrPath, "chrome-linux64", "chrome");
  return existsSync(p) ? p : null;
}

const args = parseArgs(process.argv);
let ids = args.cases;
if (args.all) {
  const { readdir } = await import("node:fs/promises");
  ids = (await readdir(join(ROOT, "cases"), { withFileTypes: true }))
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();
}
if (ids.length === 0) {
  console.error("usage: run-case.mjs <CVE-id> [--all] [--headed]");
  process.exit(2);
}

const { server, port } = await startServer();
await mkdir(join(ROOT, "findings", "raw"), { recursive: true });

const summary = [];
const stage = args.stage;
for (const id of ids) {
  const { meta } = await loadCase(id);
  const vulnBin = browserFor(args.vuln ?? meta.vulnerable, meta.browser);
  const fixedBin = browserFor(args.fixed ?? meta.fixed, meta.browser);

  if (meta.status === "not-reproducible" || meta.status === "blocked") {
    console.log(`\n== ${id}  [${meta.status}] ${meta.name}`);
    console.log(`   ${meta.reason}`);
    summary.push({ id, stage, status: meta.status, crashed: false });
    continue;
  }
  if (!vulnBin || !fixedBin) {
    console.log(`\n== ${id}  [missing builds] download with scripts/fetch_chrome.py`);
    summary.push({ id, stage, status: "missing-build", crashed: false });
    continue;
  }

  // Stage entry resolution: stages.<stage>.entry, defaulting to testcase.html
  // for stage 1 (see docs/EXPLOITATION.md §6).
  const entry =
    meta.stages?.[stage]?.entry ?? (stage === "crash" ? meta.entry ?? "testcase.html" : null);
  if (!entry || !existsSync(join(ROOT, "cases", id, entry))) {
    const status = `stage-${stage}-pending`;
    console.log(`\n== ${id}  [${status}] ${meta.name}`);
    console.log(`   no ${entry ?? `poc-${stage}.html`} for stage '${stage}' yet`);
    summary.push({ id, stage, status, crashed: false });
    continue;
  }

  console.log(`\n== ${id}  [stage: ${stage}]  ${meta.name}`);
  const runs = {};
  for (const [label, bin] of [["vulnerable", vulnBin], ["fixed", fixedBin]]) {
    const raw = join(ROOT, "findings", "raw", `${id}.${stage}.${label}.json`);
    const url = `http://127.0.0.1:${port}/cases/${id}/${entry}`;
    await runOracle({
      browser: bin,
      url,
      timeout: meta.timeoutMs ?? 20000,
      iterations: meta.iterations ?? 1,
      flags: meta.flags ?? [],
      headed: args.headed,
      out: raw,
      cores: args.cores
        ? {
            dir: join(ROOT, "findings", "raw", "cores", `${id}.${stage}.${label}`),
            coreOut: join(ROOT, "findings", "raw", `${id}.${stage}.${label}.core.txt`),
            keep: args.keepCore,
          }
        : null,
    });
    const report = JSON.parse(await readFile(raw, "utf8"));
    runs[label] = {
      crashed: report.crashed,
      crashType: report.crashType,
      results: report.results,
      pageErrors: report.pageErrors.slice(0, 10),
      core: report.core ?? null,
      durationMs: report.durationMs,
    };
    console.log(`   ${label.padEnd(10)} crash=${report.crashed} ${report.crashType ?? ""} ${JSON.stringify(report.results[0]?.result ?? null).slice(0, 160)}`);
    if (report.core) console.log(`   ${label.padEnd(10)} core: ${report.core.digest ?? report.core.note}`);
  }

  const vres = runs.vulnerable.results[0]?.result;
  const fres = runs.fixed.results[0]?.result;
  const behaviorDiff =
    vres && fres && "vulnerableBehavior" in vres && "vulnerableBehavior" in fres
      ? vres.vulnerableBehavior !== fres.vulnerableBehavior
      : false;
  // For leak/rce stages any observable difference between the two builds is
  // the evidence the PoC exists for (deterministic __LAB_RESULT, no timestamps).
  const stageEvidenceDiff =
    stage !== "crash" && vres && fres && JSON.stringify(vres) !== JSON.stringify(fres);

  const verdict =
    runs.vulnerable.crashed && !runs.fixed.crashed
      ? "reproduced"
      : runs.vulnerable.crashed && runs.fixed.crashed
        ? "crash-in-both"
        : behaviorDiff
          ? "behavioral-difference"
          : stageEvidenceDiff
            ? "stage-evidence-difference"
            : stage === "crash"
              ? "no-crash"
              : "no-evidence";

  await writeFile(
    join(ROOT, "findings", `${id}.json`),
    JSON.stringify({ id, stage, meta, verdict, runs }, null, 2) + "\n",
  );
  summary.push({ id, stage, status: verdict, crashed: runs.vulnerable.crashed, behaviorDiff });
}

server.close();
console.log(`\n===== SUMMARY (stage: ${stage}) =====`);
for (const s of summary) console.log(`${s.id}  ${s.status}`);
