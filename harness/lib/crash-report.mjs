/**
 * Core-dump analysis: the stage-1 workhorse, no sanitizer and no debug
 * symbols required.
 *
 * A release Chromium build is stripped, so a crash report cannot name the
 * function unless the frame is in a shared library that exports symbols. It
 * still gives the decisive facts for stage 1 — and for stage 3, where the
 * registers are the evidence: signal, faulting address, the instruction, the
 * module that contains the PC, and a raw backtrace. That is enough to tell a
 * browser-process UAF from an unrelated abort (OOM, sandbox, CHECK failure),
 * and a chosen RIP from an accidental one.
 *
 * The helper intentionally uses only normal binary tooling: the kernel core
 * dumper, gdb in batch mode, and the ELF symbol tables.
 */
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, statSync, unlinkSync } from "node:fs";
import { join } from "node:path";

const DEFAULT_GDB = join(process.env.HOME ?? "/root", ".local/bin/gdb");

export function findGdb(explicit) {
  if (explicit) return explicit;
  if (process.env.GDB) return process.env.GDB;
  if (existsSync(DEFAULT_GDB)) return DEFAULT_GDB;
  const which = spawnSync("sh", ["-c", "command -v gdb"], { encoding: "utf8" });
  return which.status === 0 ? which.stdout.trim() : null;
}

/** Newest core file in a directory, or null. `minMtimeMs` ignores stale cores
 *  left over from earlier runs (they must never be analysed as this run's). */
export function findCore(dir, minMtimeMs = 0) {
  try {
    const cores = readdirSync(dir)
      .filter((f) => f === "core" || f.startsWith("core."))
      .map((f) => ({ f, m: statSync(join(dir, f)).mtimeMs }))
      .filter((c) => c.m >= minMtimeMs)
      .sort((a, b) => b.m - a.m);
    return cores.length ? join(dir, cores[0].f) : null;
  } catch {
    return null;
  }
}

/**
 * Run gdb in batch mode over a core file.
 * Returns { available, text } and never throws.
 *
 * Every command is passed as its own -ex: joining them into one -ex string
 * makes gdb's parser abort mid-script, which used to drop `info registers`,
 * `x/i $rip` and the module map from the report.
 */
export function analyzeCore({ gdb, binary, core, timeoutMs = 90000 }) {
  if (!gdb) return { available: false, text: "gdb not found" };
  if (!core || !existsSync(core)) return { available: false, text: "no core file" };

  const commands = [
    "set pagination off",
    "set print symbol-loading off",
    "bt 20",
    "info registers rip rsp rbp",
    "x/i $rip",
    "info proc mappings",
  ];
  const args = ["-q", "-batch"];
  for (const c of commands) args.push("-ex", c);
  args.push(binary, core);

  const r = spawnSync(gdb, args, {
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer: 32 * 1024 * 1024,
  });
  const text = `${r.stdout ?? ""}${r.stderr ?? ""}`.trim();
  return { available: true, text, status: r.status, signal: r.signal };
}

/** Remove a core file after analysis (they can be several GB). */
export function dropCore(core) {
  if (!core) return;
  try {
    unlinkSync(core);
  } catch {}
}

/**
 * Summarise the interesting lines so the console stays readable while the
 * full output is written to a file.
 */
export function digest(text) {
  const lines = text.split("\n");
  const keep = lines.filter(
    (l) =>
      /^Program terminated|^#[0-9]+\s|^rip\s|^=>\s|received signal|Check failed|FATAL/i.test(
        l,
      ),
  );
  return keep.slice(0, 18).join("\n");
}
