/**
 * Core-dump analysis without ASAN or debug symbols.
 *
 * A release Chromium build is stripped, so a crash report cannot name the
 * function unless the frame is in a shared library that exports symbols. It
 * still gives the decisive facts for a crash-only lab: signal, faulting
 * address, the instruction, the module that contains the PC, and a raw
 * backtrace. That is enough to tell a browser-process UAF from an unrelated
 * abort (OOM, sandbox, CHECK failure).
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

/** Newest core file in a directory, or null. */
export function findCore(dir) {
  try {
    const cores = readdirSync(dir)
      .filter((f) => f === "core" || f.startsWith("core."))
      .map((f) => ({ f, m: statSync(join(dir, f)).mtimeMs }))
      .sort((a, b) => b.m - a.m);
    return cores.length ? join(dir, cores[0].f) : null;
  } catch {
    return null;
  }
}

/**
 * Run gdb in batch mode over a core file.
 * Returns { available, text } and never throws.
 */
export function analyzeCore({ gdb, binary, core, timeoutMs = 90000 }) {
  if (!gdb) return { available: false, text: "gdb not found" };
  if (!core || !existsSync(core)) return { available: false, text: "no core file" };

  const script = [
    "set pagination off",
    "set print symbol-loading off",
    "bt 20",
    "info registers rip rsp rbp",
    "x/i $rip",
    "info proc mappings",
  ].join("\n");

  const r = spawnSync(
    gdb,
    ["-q", "-batch", "-ex", script, binary, core],
    { encoding: "utf8", timeout: timeoutMs, maxBuffer: 32 * 1024 * 1024 },
  );
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
