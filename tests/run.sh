#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
GOOSE=${GOOSE:-goose}
BUILD_DIR=${BUILD_DIR:-"$ROOT/build/test"}
GOOSE_HOME=${GOOSE_HOME:-"$BUILD_DIR/goose-home"}
export GOOSE_HOME

if [ -z "${CLANG:-}" ]; then
    if [ -x /opt/homebrew/opt/llvm/bin/clang ]; then
        CLANG=/opt/homebrew/opt/llvm/bin/clang
    else
        CLANG=clang
    fi
fi
if [ -z "${READELF:-}" ]; then
    if [ -x /opt/homebrew/opt/llvm/bin/llvm-readelf ]; then
        READELF=/opt/homebrew/opt/llvm/bin/llvm-readelf
    elif command -v llvm-readelf >/dev/null 2>&1; then
        READELF=llvm-readelf
    else
        READELF=readelf
    fi
fi

mkdir -p "$BUILD_DIR"
"$GOOSE" check "$ROOT/src/gobjtool.goose"
"$GOOSE" build -o "$BUILD_DIR/gobjtool" "$ROOT/src/gobjtool.goose"
"$GOOSE" build --debug -o "$BUILD_DIR/gobjtool-debug" "$ROOT/src/gobjtool.goose"
"$GOOSE" build -o "$BUILD_DIR/model-check" "$ROOT/tests/model_check.goose"
"$BUILD_DIR/model-check" >"$BUILD_DIR/model-check.stdout"
grep -F "model pools ok" "$BUILD_DIR/model-check.stdout" >/dev/null

"$CLANG" --target=x86_64-unknown-linux-gnu -c \
    "$ROOT/tests/fixtures/basic.S" -o "$BUILD_DIR/basic.o"
python3 "$ROOT/tests/mutate-fixtures.py" "$BUILD_DIR/basic.o" "$BUILD_DIR/mutated"

"$READELF" -h -S -s -r "$BUILD_DIR/basic.o" >"$BUILD_DIR/basic.readelf"
grep -F "Advanced Micro Devices X86-64" "$BUILD_DIR/basic.readelf" >/dev/null
grep -F ".rela.text" "$BUILD_DIR/basic.readelf" >/dev/null
grep -F "external_function" "$BUILD_DIR/basic.readelf" >/dev/null
grep -F "external_object" "$BUILD_DIR/basic.readelf" >/dev/null

"$BUILD_DIR/gobjtool" check "$BUILD_DIR/basic.o"
"$BUILD_DIR/gobjtool-debug" check "$BUILD_DIR/basic.o"
"$BUILD_DIR/gobjtool" inspect "$BUILD_DIR/basic.o" >"$BUILD_DIR/basic.inspect"
"$BUILD_DIR/gobjtool" decode "$BUILD_DIR/basic.o" >"$BUILD_DIR/basic.decode"

grep -F "ELF64 x86-64 ET_REL" "$BUILD_DIR/basic.inspect" >/dev/null
grep -F "sections=7 symbols=5 relocations=3" "$BUILD_DIR/basic.inspect" >/dev/null
grep -F "name=.text type=OTHER" "$BUILD_DIR/basic.inspect" >/dev/null
grep -F "name=.symtab type=SYMTAB" "$BUILD_DIR/basic.inspect" >/dev/null
grep -F "name=entry " "$BUILD_DIR/basic.inspect" >/dev/null
grep -F "name=external_function " "$BUILD_DIR/basic.inspect" >/dev/null
grep -F "name=external_object " "$BUILD_DIR/basic.inspect" >/dev/null
grep -F "relocation section=" "$BUILD_DIR/basic.inspect" >/dev/null
grep -F "symbol=2 type=4 addend=-4 form=RELA" "$BUILD_DIR/basic.inspect" >/dev/null
grep -F "symbol=4 type=1 addend=0 form=RELA" "$BUILD_DIR/basic.inspect" >/dev/null
grep -F "offset=4 length=5 kind=call" "$BUILD_DIR/basic.decode" >/dev/null
grep -F "offset=9 length=7 kind=lea-rip" "$BUILD_DIR/basic.decode" >/dev/null
grep -F "offset=17 length=1 kind=return" "$BUILD_DIR/basic.decode" >/dev/null

"$BUILD_DIR/gobjtool" check "$BUILD_DIR/mutated/extended-sections.o"
"$BUILD_DIR/gobjtool-debug" check "$BUILD_DIR/mutated/extended-symbol.o"
"$BUILD_DIR/gobjtool" inspect "$BUILD_DIR/mutated/rel.o" >"$BUILD_DIR/rel.inspect"
grep -F "form=REL" "$BUILD_DIR/rel.inspect" >/dev/null

printf 'not ELF\n' >"$BUILD_DIR/not-elf"
if "$BUILD_DIR/gobjtool" check "$BUILD_DIR/not-elf" \
        >"$BUILD_DIR/not-elf.stdout" 2>"$BUILD_DIR/not-elf.stderr"; then
    echo "tests: non-ELF input unexpectedly succeeded" >&2
    exit 1
fi
grep -F "truncated ELF header" "$BUILD_DIR/not-elf.stderr" >/dev/null

dd if="$BUILD_DIR/basic.o" of="$BUILD_DIR/truncated.o" bs=1 count=63 2>/dev/null
if "$BUILD_DIR/gobjtool-debug" check "$BUILD_DIR/truncated.o" \
        >"$BUILD_DIR/truncated.stdout" 2>"$BUILD_DIR/truncated.stderr"; then
    echo "tests: truncated ELF input unexpectedly succeeded" >&2
    exit 1
fi
grep -F "truncated ELF header" "$BUILD_DIR/truncated.stderr" >/dev/null

expect_failure() {
    file=$1
    diagnostic=$2
    name=$(basename "$file" .o)
    if "$BUILD_DIR/gobjtool-debug" check "$file" \
            >"$BUILD_DIR/$name.stdout" 2>"$BUILD_DIR/$name.stderr"; then
        echo "tests: $name unexpectedly succeeded" >&2
        exit 1
    fi
    grep -F "$diagnostic" "$BUILD_DIR/$name.stderr" >/dev/null
}

expect_failure "$BUILD_DIR/mutated/wrong-machine.o" \
    "expected an x86-64 ELF object"
expect_failure "$BUILD_DIR/mutated/bad-section-table.o" \
    "truncated ELF section table"
expect_failure "$BUILD_DIR/mutated/bad-section-name-index.o" \
    "invalid section-name string table index"
expect_failure "$BUILD_DIR/mutated/bad-alignment.o" \
    "has invalid alignment"
expect_failure "$BUILD_DIR/mutated/bad-section-range.o" \
    "lies outside the file"
expect_failure "$BUILD_DIR/mutated/bad-symbol-name.o" \
    "invalid name for symbol"
expect_failure "$BUILD_DIR/mutated/bad-relocation-symbol.o" \
    "invalid symbol index in relocation"

echo "ok: native ELF64 reader, x86-64 decoder, and typed analysis model"
