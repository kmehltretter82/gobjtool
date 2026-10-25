# gobjtool implementation and qualification gates

The project is complete only when a Linux x86-64 kernel configured with ORC
unwinding, stack validation, and the applicable mitigations builds and boots
using `gobjtool`, with upstream-compatible diagnostics and generated ELF
sections. The stages below are cumulative.

1. **Native ELF64 core**
   Parse and rewrite `ET_REL` files without libelf: headers, sections, string
   tables, symbols, extended indices, REL/RELA entries, section creation and
   atomic replacement. Differentially check malformed and valid objects.
2. **x86-64 instruction model**
   Decode every instruction class needed by upstream `objtool`, including
   stack operations and direct/indirect control transfers. Build indexed
   instruction and symbol pools with typed, narrow references.
3. **Control flow and stack validation**
   Resolve relocations, alternatives, jump tables and exception-table edges;
   propagate CFI state to a fixed point and match upstream diagnostics.
4. **ORC generation**
   Generate `.orc_unwind`, `.orc_unwind_ip` and their relocation sections,
   byte- or semantically identical to upstream across GCC and Clang corpora.
5. **Kernel annotations and security passes**
   Implement static-call/fentry annotations and retpoline, return-thunk,
   straight-line-speculation, IBT, uaccess and `noinstr` validation.
6. **Whole-kernel differential qualification**
   Run both tools over every translation unit, linked module and `vmlinux.o`
   from representative GCC and Clang configurations. Compare exit status,
   diagnostics and every changed or generated section.
7. **Boot and runtime qualification**
   Boot generated kernels under QEMU, exercise ORC stack traces, livepatch and
   relevant selftests, and retain reproducible build/configuration evidence.
8. **Adversarial qualification**
   Fuzz ELF structure, relocation graphs and instruction streams in optimized
   and checked-debug builds. No malformed input may cause an abort outside a
   deliberate diagnostic path or leave a partially rewritten object.

## Current status

The read-only portion of Stage 1 is implemented and checked across 1,143
kernel objects; the ELF writer remains outstanding. Stage 2 now has a native,
Linux-table-derived length decoder, objtool instruction classification, stack
operation extraction, typed analysis pools, and an initial direct-branch CFG.
Its 2,355,401 decoded instruction boundaries matched Linux `insn.c` exactly on
the current corpus. Full symbol/relocation target resolution, alternatives,
stack-state propagation, ORC output, security passes, and kernel integration
remain outstanding; no drop-in compatibility is claimed yet.
