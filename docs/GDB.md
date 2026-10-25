# Debugging release builds (gdb, cores, normal binary tooling)

This is the lab's primary debugger workflow for **all three stages**: crash
evidence (stage 1), corroborating a leaked value (stage 2) and verifying
control of registers/payloads (stage 3). Everything here uses the shipped
release binary plus normal binary tooling: the kernel core dumper, `gdb` in
batch and interactive mode, and the ELF symbol tables. No sanitizer build is
used or required anywhere in the lab.

## 1. Get a usable gdb

The distribution package is enough, and it can be installed without root by
extracting the `.deb` into a private prefix:

```bash
mkdir -p /tmp/gdbdeb && cd /tmp/gdbdeb
apt-get download gdb libbabeltrace1 libipt2 libdebuginfod1t64 libsource-highlight4t64
mkdir -p root
for d in *.deb; do dpkg-deb -x "$d" root; done
cp -a root/. ~/.local/gdb/

cat > ~/.local/bin/gdb <<'EOF'
#!/bin/sh
GDBROOT="$HOME/.local/gdb"
export LD_LIBRARY_PATH="$GDBROOT/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$GDBROOT/usr/bin/gdb" --data-directory="$GDBROOT/usr/share/gdb" "$@"
EOF
chmod +x ~/.local/bin/gdb
gdb --version
```

The wrapper matters: `--data-directory` points gdb at the extracted support
files, and `LD_LIBRARY_PATH` supplies the extra libraries.

`ptrace_scope` must allow attaching to a child; check
`cat /proc/sys/kernel/yama/ptrace_scope`. `0` (or `1` when the tracer is the
parent) works. The harness spawns the browser itself, so it is the parent.

## 2. Let the kernel write a core

`ulimit -c` defaults to `0` on most systems and `/proc/sys/kernel/core_pattern`
is usually `core`, i.e. a file named `core` in the crashing process's working
directory. The self-driving harness therefore:

1. spawns the browser through `sh -c 'ulimit -c unlimited; exec "$@"'`,
2. sets the browser's working directory to the temporary profile,
3. passes `--disable-breakpad` so Crashpad does not consume the signal.

## 3. Analyse it

```bash
node harness/selfdrive-110922.mjs --browser /usr/lib/chromium/chromium \
  --attempts 3 --timeout 15000
```

On a crash the harness finds the newest `core*` file, runs

```
gdb -q -batch -ex "bt 20" -ex "info registers rip rsp rbp" -ex "x/i $rip" \
    -ex "info proc mappings" <chrome> <core>
```

and writes the full output to `findings/raw/<CVE>.attemptN.core.txt`. The
console shows a short digest. `--keep-core` preserves the file for manual
inspection; by default it is deleted after analysis (cores are multi-GB).

A release Chrome is stripped, so frames inside `chrome` are addresses without
names. The report still answers the questions this lab needs:

- which signal killed the process (`SIGSEGV` vs. `SIGABRT` from a CHECK),
- the faulting address and instruction,
- which module contains the PC (`info proc mappings`),
- whether the crash is in the browser process or a child.

To get names for Chromium functions, build `symbol_level=1` or fetch the
matching Breakpad symbols; without them, compare the PC against
`objdump -d` and the fix commit.

## 4. Live debugging: breakpoints, watchpoints (stages 1–3)

Cores are what happens *after* a fault; the stages need to see the bug *before*
it faults. The recipe without any sanitizer:

1. **Get addresses from the patch.** Read the fix diff, find the touched
   functions/files, and locate them in the shipped binary or its libraries:

   ```bash
   objdump -d --disassemble=<mangled> builds/.../chrome | head
   readelf -Ws builds/.../lib*.so | grep <symbol>
   ```

   Chromium's main binary is stripped, so prefer symbols in `.so`s (base::,
   blink core libraries) and module-relative offsets: record the load address
   with `info proc mappings` and compute `base + offset` per run.

2. **Run the browser under gdb** and break at those addresses (or use
   `gdb -p <pid>` on an already-running lab browser — `ptrace_scope` must
   allow it):

   ```bash
   gdb -q --args builds/.../chrome --user-data-dir=/tmp/lab-profile \
       about:blank
   (gdb) set pagination off
   (gdb) break *0x55...            # or: break blink::Foo::Bar if you have symbols
   (gdb) run
   ```

3. **Drive the testcase from the page** while gdb is stopped/continued; the
   harness (`run-case.mjs`) can attach to the same URL, but for breakpoints it
   is simpler to run the browser manually and load
   `http://127.0.0.1:<port>/cases/<CVE>/<entry>`.

4. **Watch the dangling slot** (the stage-1/2 workhorse for UAFs):

   ```
   (gdb) watch *(long*)0x7f...      # written after free? who and with what
   (gdb) info breakpoints           # hit counts across the window
   ```

5. **Conditional breaks** keep a hot function quiet until the interesting
   state: `break *0x... if $rdi == 0x1234`.

6. **Corroborate a leak (stage 2):** break on the path the patch touches,
   print the value at that instant (`x/gx $rax`, `x/s` for strings), and check
   it against what the page published in `__LAB_RESULT`.

7. **Verify hijack/payload (stage 3):** on the controlled crash, `info
   registers rip rsp rbp`, `x/i $rip`, `info registers rdi rsi rdx rcx` — the
   evidence is that these equal the values the PoC chose.

Batch equivalent for a core is in §3; both write to `findings/raw/`.

## 5. What this cannot do

A use-after-free only segfaults if the freed memory is unmapped or reused as an
incompatible object. PartitionAlloc keeps freed slots mapped, so a deterministic
release-build crash is not guaranteed. That is exactly why the lab combines
two normal techniques instead of waiting: reclaim the slot with a controlled
object of the same size (shaping, from JS) and breakpoint/watch the use (this
page). The C++ regression test triggers the free and the reuse in one stack,
so it is the deterministic reproduction to run under gdb.

## 6. Validating the pipeline

A trivial crash confirms the plumbing (core written, gdb resolves the frame):

```bash
printf 'int main(void){volatile int*p=0;*p=1;}\n' > /tmp/crashy.c
cc -g -o /tmp/crashy /tmp/crashy.c
node harness/selfdrive-110922.mjs --browser /tmp/crashy --timeout 4000
# -> Program terminated with signal SIGSEGV, Segmentation fault.
#    #0  main () at crashy.c:1
#    attempts=1 crashed=1
```
