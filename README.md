# gobjtool

`gobjtool` is a native Goose reimplementation of Linux's `objtool`, beginning
with x86-64. It is intended to become a drop-in kernel-build host tool rather
than a wrapper around upstream `objtool` or `libelf`.

The current vertical slice performs checked parsing of little-endian ELF64
relocatable objects and native, table-driven decoding of every executable
x86-64 section. It includes section tables and names, regular and extended
symbol section indices, REL/RELA relocations, Linux-derived opcode attributes,
objtool instruction classification, stack-operation extraction, and an initial
control-flow graph stored in typed Goose pools.

The instruction decoder has been differentially checked against Linux's own
`arch/x86/lib/insn.c` over 1,143 kernel objects: all 2,355,401 instruction
boundaries matched. The procedure and provenance are recorded in
[`docs/decoder-validation.md`](docs/decoder-validation.md). Stack-state
validation and ELF rewriting are not complete, so this remains experimental
and is not yet a replacement for `objtool`.

## Build and test

Goose is selected from `.goose-toolchain/goose`, the parent workspace, or
`PATH`, in that order:

```sh
make check
make test
make build
```

An existing x86-64 kernel build can be used as a real-object parsing corpus:

```sh
make corpus KERNEL_BUILD=/path/to/kernel-build
```

Inspect an x86-64 object with:

```sh
build/gobjtool inspect file.o
```

Inspect its native instruction classification with:

```sh
build/gobjtool decode file.o
```

## Scope

The required end state is an x86-64-compatible implementation with its own
ELF reader/writer, instruction model, control-flow graph, stack-state analysis,
ORC generation, kernel security validations, whole-build differential tests,
boot qualification, and malformed-input fuzzing. See
[`docs/roadmap.md`](docs/roadmap.md) for the gates; passing the initial ELF
reader tests is deliberately not considered project completion.

## License

GPL-2.0-or-later.
