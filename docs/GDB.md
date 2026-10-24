# Debugging release builds without ASAN

ASAN is the best detector for memory-safety bugs, but it needs a multi-hour
Chromium build. Most of the work in this lab can be done with the shipped
release binary plus normal binary tooling: the kernel core dumper, `gdb`, and
the ELF symbol tables. This page documents that path.

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

## 4. What this cannot do

A use-after-free only segfaults if the freed memory is unmapped or reused as an
incompatible object. PartitionAlloc keeps freed slots mapped, so a deterministic
release-build crash is not guaranteed. That is exactly why the C++ regression
test (which triggers the free and the reuse in one stack) is the canonical
reproduction: under gdb it can be breakpointed without any sanitizer. ASAN only
makes the report automatic.

## 5. Validating the pipeline

A trivial crash confirms the plumbing (core written, gdb resolves the frame):

```bash
printf 'int main(void){volatile int*p=0;*p=1;}\n' > /tmp/crashy.c
cc -g -o /tmp/crashy /tmp/crashy.c
node harness/selfdrive-110922.mjs --browser /tmp/crashy --timeout 4000
# -> Program terminated with signal SIGSEGV, Segmentation fault.
#    #0  main () at crashy.c:1
#    attempts=1 crashed=1
```
