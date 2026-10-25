#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Create deterministic valid variants and malformed ELF64 regression inputs."""

from __future__ import annotations

import struct
import sys
from pathlib import Path


def align(buf: bytearray, amount: int) -> None:
    buf.extend(b"\0" * (-len(buf) % amount))


source = Path(sys.argv[1])
out_dir = Path(sys.argv[2])
out_dir.mkdir(parents=True, exist_ok=True)
original = bytearray(source.read_bytes())


def u16(data: bytes | bytearray, at: int) -> int:
    return struct.unpack_from("<H", data, at)[0]


def u64(data: bytes | bytearray, at: int) -> int:
    return struct.unpack_from("<Q", data, at)[0]


shoff = u64(original, 40)
shentsize = u16(original, 58)
shnum = u16(original, 60)
shstrndx = u16(original, 62)
assert shentsize == 64 and shnum > 0 and shstrndx < shnum


def section(data: bytes | bytearray, index: int) -> tuple[int, ...]:
    return struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shentsize)


sections = [section(original, index) for index in range(shnum)]
shstr = sections[shstrndx]
shstr_data = bytes(original[shstr[4] : shstr[4] + shstr[5]])


def c_string(data: bytes, at: int) -> str:
    end = data.index(0, at)
    return data[at:end].decode("ascii")


names = [c_string(shstr_data, entry[0]) for entry in sections]
by_name = {name: index for index, name in enumerate(names)}


def write(name: str, data: bytearray) -> None:
    (out_dir / name).write_bytes(data)


# ELF extended section count and extended shstrndx use section zero's sh_size
# and sh_link. Small counts exercise the representation without a 65K fixture.
extended = bytearray(original)
struct.pack_into("<H", extended, 60, 0)
struct.pack_into("<H", extended, 62, 0xFFFF)
struct.pack_into("<Q", extended, shoff + 32, shnum)
struct.pack_into("<I", extended, shoff + 40, shstrndx)
write("extended-sections.o", extended)


# Convert one RELA section into a well-formed REL section. Its first 16 bytes
# are exactly Elf64_Rel; the former addend bytes become unreferenced padding.
rel = bytearray(original)
rela_data_index = by_name[".rela.data"]
rela_data_header = shoff + rela_data_index * shentsize
struct.pack_into("<I", rel, rela_data_header + 4, 9)   # SHT_REL
struct.pack_into("<Q", rel, rela_data_header + 32, 16)
struct.pack_into("<Q", rel, rela_data_header + 56, 16)
write("rel.o", rel)


# Add SHT_SYMTAB_SHNDX and make symbol 1 use it. The old section table remains
# as inert bytes; a new table points at a copied and extended string table.
symtab_index = by_name[".symtab"]
symtab = sections[symtab_index]
symbol_count = symtab[5] // symtab[9]
assert symbol_count > 1 and symtab[9] == 24
extended_symbol = bytearray(original)
struct.pack_into("<H", extended_symbol, symtab[4] + 24 + 6, 0xFFFF)

new_name_offset = len(shstr_data)
align(extended_symbol, 8)
new_strings_offset = len(extended_symbol)
new_name = b".symtab_shndx\0"
extended_symbol.extend(shstr_data + new_name)
align(extended_symbol, 4)
shndx_offset = len(extended_symbol)
indices = [0] * symbol_count
indices[1] = by_name[".text"]
for value in indices:
    extended_symbol.extend(struct.pack("<I", value))
align(extended_symbol, 8)
new_shoff = len(extended_symbol)
old_headers = bytearray(original[shoff : shoff + shnum * shentsize])
struct.pack_into("<Q", old_headers, shstrndx * shentsize + 24,
                 new_strings_offset)
struct.pack_into("<Q", old_headers, shstrndx * shentsize + 32,
                 len(shstr_data) + len(new_name))
extended_symbol.extend(old_headers)
extended_symbol.extend(struct.pack(
    "<IIQQQQIIQQ",
    new_name_offset, 18, 0, 0, shndx_offset, symbol_count * 4,
    symtab_index, 0, 4, 4,
))
struct.pack_into("<Q", extended_symbol, 40, new_shoff)
struct.pack_into("<H", extended_symbol, 60, shnum + 1)
write("extended-symbol.o", extended_symbol)


wrong_machine = bytearray(original)
struct.pack_into("<H", wrong_machine, 18, 183)  # EM_AARCH64
write("wrong-machine.o", wrong_machine)

bad_shoff = bytearray(original)
struct.pack_into("<Q", bad_shoff, 40, len(original) + 1)
write("bad-section-table.o", bad_shoff)

bad_shstr = bytearray(original)
struct.pack_into("<H", bad_shstr, 62, shnum)
write("bad-section-name-index.o", bad_shstr)

bad_align = bytearray(original)
text_header = shoff + by_name[".text"] * shentsize
struct.pack_into("<Q", bad_align, text_header + 48, 3)
write("bad-alignment.o", bad_align)

bad_range = bytearray(original)
struct.pack_into("<Q", bad_range, text_header + 24, len(original) + 1)
write("bad-section-range.o", bad_range)

bad_symbol_name = bytearray(original)
strings = sections[symtab[6]]
struct.pack_into("<I", bad_symbol_name, symtab[4] + 24, strings[5])
write("bad-symbol-name.o", bad_symbol_name)

bad_relocation = bytearray(original)
rela_text = sections[by_name[".rela.text"]]
old_info = u64(bad_relocation, rela_text[4] + 8)
bad_info = (symbol_count << 32) | (old_info & 0xFFFFFFFF)
struct.pack_into("<Q", bad_relocation, rela_text[4] + 8, bad_info)
write("bad-relocation-symbol.o", bad_relocation)
