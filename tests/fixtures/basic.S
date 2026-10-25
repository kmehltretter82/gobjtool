/* SPDX-License-Identifier: GPL-2.0-or-later */

        .text
        .globl  entry
        .type   entry,@function
entry:
        pushq   %rbp
        movq    %rsp,%rbp
        call    external_function
        leaq    object(%rip),%rax
        popq    %rbp
        retq
        .size   entry,.-entry

        .data
        .globl  object
        .type   object,@object
        .p2align 3
object:
        .quad   external_object
        .size   object,8
