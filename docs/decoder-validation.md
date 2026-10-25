# Native decoder validation record

The checked-in x86 attribute tables were generated from Linux revision
`ca70a0f42ee492bd4e834f9e77aa603e64707d12`. The generated
`inat-tables.c` input had SHA-256
`5bc098c57c3bfaa8d3fbd05f6d7703c5573417431a48160a194961e7cf334525`;
both values are embedded in `src/x86_tables.goose`.

On 2026-10-26, `gobjtool` was compared with the decoder in that Linux tree over
1,143 little-endian x86-64 `ET_REL` kernel objects. The comparison covered
2,355,401 instructions and found no boundary differences:

```text
decoder oracle: objects=1143 instructions=2355401 failed=0
```

The test-only `tests/x86-decode-oracle.c` directly includes Linux `inat.c` and
`insn.c`; production `gobjtool` neither links nor calls any C decoder. Build the
oracle against the selected Linux source and object trees, supplying any host
compatibility flags required by the platform:

```sh
cc $HOST_CFLAGS -std=gnu11 -O2 \
  -I"$LINUX_SRC/tools/arch/x86/lib" \
  -I"$LINUX_SRC/tools/arch/x86/include" \
  -I"$LINUX_SRC/tools/include" \
  -I"$LINUX_SRC/tools/include/uapi" \
  -I"$LINUX_SRC/include/uapi" \
  -I"$KERNEL_BUILD/arch/x86/include/generated/uapi" \
  -I"$KERNEL_BUILD/arch/x86/lib" \
  tests/x86-decode-oracle.c -o build/x86-decode-oracle
```

Then compare every executable section with the native Goose decoder:

```sh
python3 tests/decoder-oracle.py \
  --gobjtool build/gobjtool \
  --linux-decoder build/x86-decode-oracle \
  "$KERNEL_BUILD"
```

Using `llvm-objdump` is supported as a lighter independent check, but it is not
the authoritative parity oracle: disassemblers may split a valid instruction
at a relocation or symbol boundary, such as displaying a `lock` prefix as a
standalone byte.
