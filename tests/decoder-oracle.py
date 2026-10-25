#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Compare gobjtool's instruction boundaries with an independent objdump."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path


SECTION = re.compile(r"^Disassembly of section (.+):$")
OBJDUMP_INSN = re.compile(r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}(?:\s+|$))+)")
GOBJTOOL_INSN = re.compile(
    r"^instruction section=(\S+) offset=([0-9]+) length=([0-9]+)\s"
)


def is_x86_64_rel(path: Path) -> bool:
    try:
        header = path.read_bytes()[:20]
    except OSError:
        return False
    return (
        len(header) == 20
        and header[:7] == b"\x7fELF\x02\x01\x01"
        and struct.unpack_from("<H", header, 16)[0] == 1
        and struct.unpack_from("<H", header, 18)[0] == 62
    )


def find_executable(value: str) -> str:
    if os.sep in value:
        path = Path(value).expanduser().resolve()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    found = shutil.which(value)
    if found:
        return found
    raise SystemExit(f"decoder oracle: executable not found: {value}")


def run(command: list[str], input_bytes: bytes | None = None) -> str:
    result = subprocess.run(
        command,
        input=input_bytes,
        stdin=subprocess.DEVNULL if input_bytes is None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"command exited {result.returncode}: {' '.join(command)}\n"
            f"{result.stderr.decode(errors='replace')}"
        )
    return result.stdout.decode(errors="replace")


def native_boundaries(output: str) -> list[tuple[str, int, int]]:
    result: list[tuple[str, int, int]] = []
    for line in output.splitlines():
        match = GOBJTOOL_INSN.match(line)
        if match:
            result.append((match.group(1), int(match.group(2)), int(match.group(3))))
    return result


def objdump_boundaries(output: str) -> list[tuple[str, int, int]]:
    result: list[tuple[str, int, int]] = []
    section: str | None = None
    for line in output.splitlines():
        section_match = SECTION.match(line)
        if section_match:
            section = section_match.group(1)
            continue
        instruction_match = OBJDUMP_INSN.match(line)
        if section is not None and instruction_match:
            raw = instruction_match.group(2).split()
            result.append((section, int(instruction_match.group(1), 16), len(raw)))
    return result


def executable_sections(path: Path) -> list[tuple[str, bytes]]:
    data = path.read_bytes()
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise RuntimeError(f"not a little-endian ELF64 object: {path}")
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    entry_size = struct.unpack_from("<H", data, 58)[0]
    count = struct.unpack_from("<H", data, 60)[0]
    names_index = struct.unpack_from("<H", data, 62)[0]
    if entry_size < 64 or section_offset + entry_size > len(data):
        raise RuntimeError(f"invalid section table: {path}")
    if count == 0:
        count = struct.unpack_from("<Q", data, section_offset + 32)[0]
    if names_index == 0xFFFF:
        names_index = struct.unpack_from("<I", data, section_offset + 40)[0]
    if count == 0 or names_index >= count or section_offset + entry_size * count > len(data):
        raise RuntimeError(f"invalid section count or name table: {path}")

    def header(index: int) -> tuple[int, int, int, int, int]:
        at = section_offset + entry_size * index
        name = struct.unpack_from("<I", data, at)[0]
        kind = struct.unpack_from("<I", data, at + 4)[0]
        flags = struct.unpack_from("<Q", data, at + 8)[0]
        offset = struct.unpack_from("<Q", data, at + 24)[0]
        size = struct.unpack_from("<Q", data, at + 32)[0]
        if kind != 8 and (offset > len(data) or size > len(data) - offset):
            raise RuntimeError(f"section outside file: {path}")
        return name, kind, flags, offset, size

    _, names_kind, _, names_offset, names_size = header(names_index)
    if names_kind == 8:
        raise RuntimeError(f"section-name table is NOBITS: {path}")
    names = data[names_offset : names_offset + names_size]
    result: list[tuple[str, bytes]] = []
    for index in range(count):
        name_at, kind, flags, offset, size = header(index)
        if not flags & 4 or not size:
            continue
        if kind == 8 or name_at >= len(names):
            raise RuntimeError(f"invalid executable section: {path}")
        name_end = names.find(b"\0", name_at)
        if name_end < 0:
            raise RuntimeError(f"unterminated section name: {path}")
        name = names[name_at:name_end].decode(errors="surrogateescape")
        result.append((name, data[offset : offset + size]))
    return result


def linux_boundaries(binary: str, obj: Path) -> list[tuple[str, int, int]]:
    result: list[tuple[str, int, int]] = []
    for section, data in executable_sections(obj):
        for line in run([binary], data).splitlines():
            fields = line.split()
            if len(fields) != 2:
                raise RuntimeError(f"malformed Linux decoder output: {line}")
            result.append((section, int(fields[0]), int(fields[1])))
    return result


def first_difference(
    expected: list[tuple[str, int, int]], actual: list[tuple[str, int, int]]
) -> str:
    for index, (want, got) in enumerate(zip(expected, actual)):
        if want != got:
            return f"instruction {index}: objdump={want} gobjtool={got}"
    if len(expected) != len(actual):
        return f"instruction count: objdump={len(expected)} gobjtool={len(actual)}"
    return ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path, help="an object or directory containing objects")
    parser.add_argument("--gobjtool", default="build/gobjtool")
    parser.add_argument("--objdump", default="llvm-objdump")
    parser.add_argument(
        "--linux-decoder",
        help="test-only frontend built from Linux insn.c; preferred over objdump",
    )
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    gobjtool = find_executable(args.gobjtool)
    objdump = find_executable(args.objdump) if not args.linux_decoder else ""
    linux_decoder = find_executable(args.linux_decoder) if args.linux_decoder else ""
    source = args.input.expanduser().resolve()
    if source.is_file():
        objects = [source] if is_x86_64_rel(source) else []
    elif source.is_dir():
        objects = [path for path in sorted(source.rglob("*.o")) if is_x86_64_rel(path)]
    else:
        raise SystemExit(f"decoder oracle: input does not exist: {source}")
    if args.limit < 0:
        raise SystemExit("decoder oracle: --limit must not be negative")
    if args.limit:
        objects = objects[: args.limit]
    if not objects:
        raise SystemExit("decoder oracle: no x86-64 ELF64 ET_REL inputs")

    instructions = 0
    failures = 0
    for obj in objects:
        try:
            expected = (
                linux_boundaries(linux_decoder, obj)
                if linux_decoder
                else objdump_boundaries(run([objdump, "-d", str(obj)]))
            )
            actual = native_boundaries(run([gobjtool, "decode", str(obj)]))
        except RuntimeError as error:
            print(f"FAIL {obj}: {error}", file=sys.stderr)
            failures += 1
            continue
        difference = first_difference(expected, actual)
        if difference:
            print(f"FAIL {obj}: {difference}", file=sys.stderr)
            failures += 1
        instructions += len(expected)

    print(
        f"decoder oracle: objects={len(objects)} instructions={instructions} "
        f"failed={failures}"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
