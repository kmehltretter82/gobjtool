# Upstream objtool oracle

`tests/upstream-oracle.py` runs `gobjtool` and Linux's host `objtool` over the
same sorted corpus of x86-64 ELF64 relocatable objects. The default reader mode
is deliberately non-mutating: `gobjtool check` only reads each file, upstream
`objtool` is forced to use `--dry-run`, and the harness verifies each source
object's SHA-256 before and after both invocations.

## Quick start

Build `gobjtool`, then identify an upstream `objtool` and a kernel build tree:

```sh
make -C gobjtool build

OBJTOOL=/path/to/linux-build/tools/objtool/objtool \
CORPUS=/path/to/linux-build \
python3 gobjtool/tests/upstream-oracle.py
```

The executable and corpus can instead be supplied explicitly:

```sh
python3 gobjtool/tests/upstream-oracle.py \
    --gobjtool gobjtool/build/gobjtool \
    --objtool /path/to/objtool \
    --limit 100 \
    /path/to/linux-build
```

Only files whose headers identify little-endian x86-64 `ET_REL` objects are
selected. Host Mach-O objects and ELF files for other architectures are
skipped. `--pattern` and `--limit` provide deterministic smaller probes.

The upstream action defaults to `--stackval --orc`. Override it without adding
`--dry-run`; the harness adds that option. Output and backup options are always
rejected so neither tool can redirect a write outside its managed input copy:

```sh
OBJTOOL_ARGS='--stackval' python3 gobjtool/tests/upstream-oracle.py /path/to/build
```

Reader mode checks the overlap implemented today: `gobjtool` must safely accept
every valid ELF object. It still runs upstream `objtool`, but only records its
rejections and diagnostics. A generic action replay can legitimately reject an
already-processed or specially linked kernel object when it lacks that object's
original Kbuild action set; that is not evidence of an ELF-reader mismatch.
`gobjtool` does not yet implement the instruction or stack semantics needed to
compare those outcomes.

`--mode parity` is the next gate. It requires identical exit status, stdout and
normalized stderr. Enable it only as the corresponding
`objtool` actions become implemented:

```sh
python3 gobjtool/tests/upstream-oracle.py --mode parity /path/to/build
```

## ORC writer hook

`--mode orc` never mutates the corpus. It copies each input into a fresh
temporary directory, lets both tools rewrite their own copy, and compares the
raw `.orc_unwind`, `.orc_unwind_ip`, and `.rela.orc_unwind_ip` payloads. Until
the native writer exists this mode intentionally refuses to run. Once it does,
provide its action arguments explicitly:

```sh
GOBJTOOL_ORC_ARGS='check --orc' \
python3 gobjtool/tests/upstream-oracle.py --mode orc /path/to/build
```

Use `--orc-sections` to alter the comparison set. Raw equality is the initial
gate; if independent ELF layouts later make relocation symbol indices differ,
add a separately reviewed semantic-relocation comparison rather than weakening
this one silently.

## Building the upstream oracle

An upstream Linux tree can build `objtool` outside its source directory:

```sh
LINUX_SRC=/path/to/linux
OBJTOOL_BUILD=$(mktemp -d)
make -C "$LINUX_SRC/tools/objtool" \
    O="$OBJTOOL_BUILD" ARCH=x86 SRCARCH=x86 -j8
```

Use `O=`, not a command-line `OUTPUT=` assignment: GNU Make propagates the
latter into the recursive `libsubcmd` build and gives it the wrong output
target. The host needs the development packages for `libelf` and, when
enabled, `libxxhash`. On macOS, pass the relevant Homebrew include and library
paths through `HOSTCFLAGS`, `HOSTLDFLAGS`, and `LIBRARY_PATH`.

A configured x86-64 kernel object directory provides the corpus. Its source
files are immutable oracle inputs; mutation tests must always use temporary
copies.
