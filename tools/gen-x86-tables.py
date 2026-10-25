#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Translate Linux's generated inat-tables.c into native Goose tables.

The runtime decoder has no dependency on Linux headers or C code. This tool
is only used when refreshing the checked-in table data after updating the
pinned Linux opcode map.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import pathlib
import re


CONSTANTS = {
    "INAT_PFX_OPNDSZ": 1,
    "INAT_PFX_REPE": 2,
    "INAT_PFX_REPNE": 3,
    "INAT_PFX_LOCK": 4,
    "INAT_PFX_CS": 5,
    "INAT_PFX_DS": 6,
    "INAT_PFX_ES": 7,
    "INAT_PFX_FS": 8,
    "INAT_PFX_GS": 9,
    "INAT_PFX_SS": 10,
    "INAT_PFX_ADDRSZ": 11,
    "INAT_PFX_REX": 12,
    "INAT_PFX_VEX2": 13,
    "INAT_PFX_VEX3": 14,
    "INAT_PFX_EVEX": 15,
    "INAT_PFX_REX2": 16,
    "INAT_PFX_XOP": 17,
    "INAT_IMM_BYTE": 1,
    "INAT_IMM_WORD": 2,
    "INAT_IMM_DWORD": 3,
    "INAT_IMM_QWORD": 4,
    "INAT_IMM_PTR": 5,
    "INAT_IMM_VWORD32": 6,
    "INAT_IMM_VWORD": 7,
    "INAT_MODRM": 1 << 15,
    "INAT_FORCE64": 1 << 16,
    "INAT_SCNDIMM": 1 << 17,
    "INAT_MOFFSET": 1 << 18,
    "INAT_VARIANT": 1 << 19,
    "INAT_VEXOK": 1 << 20,
    "INAT_XOPOK": 1 << 20,
    "INAT_VEXONLY": 1 << 21,
    "INAT_EVEXONLY": 1 << 22,
    "INAT_NO_REX2": 1 << 23,
    "INAT_REX2_VARIANT": 1 << 24,
    "INAT_EVEX_SCALABLE": 1 << 25,
    "INAT_INV64": 1 << 26,
}

TABLE_START = re.compile(
    r"^const insn_attr_t (inat_[A-Za-z0-9_]+)"
    r"\[(INAT_OPCODE_TABLE_SIZE|INAT_GROUP_TABLE_SIZE)\] = \{$"
)
ENTRY = re.compile(r"^\s*\[(0x[0-9a-fA-F]+|[0-9]+)\]\s*=\s*(.+),$")


def eval_expr(text: str) -> int:
    """Evaluate the deliberately tiny expression language emitted by awk."""

    def visit(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.Name) and node.id in CONSTANTS:
            return CONSTANTS[node.id]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return visit(node.left) | visit(node.right)
        if isinstance(node, ast.Call) and len(node.args) == 1 and not node.keywords:
            if not isinstance(node.func, ast.Name):
                raise ValueError(f"unsupported call in attribute expression: {text}")
            value = visit(node.args[0])
            if node.func.id == "INAT_MAKE_PREFIX":
                return value
            if node.func.id == "INAT_MAKE_ESCAPE":
                return value << 5
            if node.func.id == "INAT_MAKE_GROUP":
                return (value << 7) | CONSTANTS["INAT_MODRM"]
            if node.func.id == "INAT_MAKE_IMM":
                return value << 12
        raise ValueError(f"unsupported attribute expression: {text}")

    return visit(ast.parse(text, mode="eval"))


def read_tables(path: pathlib.Path) -> dict[str, list[int]]:
    tables: dict[str, list[int]] = {}
    current: list[int] | None = None
    current_name = ""

    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        start = TABLE_START.match(line)
        if start:
            current_name = start.group(1)
            size = 256 if start.group(2) == "INAT_OPCODE_TABLE_SIZE" else 8
            current = [0] * size
            if current_name in tables:
                raise ValueError(f"{path}:{line_number}: duplicate table {current_name}")
            continue
        if current is None:
            continue
        if line == "};":
            tables[current_name] = current
            current = None
            current_name = ""
            continue
        entry = ENTRY.match(line)
        if not entry:
            if not line.strip() or line.lstrip().startswith("/*"):
                continue
            raise ValueError(f"{path}:{line_number}: unexpected table line: {line}")
        index = int(entry.group(1), 0)
        if index >= len(current):
            raise ValueError(f"{path}:{line_number}: table index {index} is out of range")
        current[index] = eval_expr(entry.group(2))

    if current is not None:
        raise ValueError(f"{path}: unterminated table {current_name}")
    if "inat_primary_table" not in tables:
        raise ValueError(f"{path}: no inat_primary_table found")
    return tables


def emit_array(name: str, values: list[int]) -> list[str]:
    lines = [f"const {name}: u32[{len(values)}] = ["]
    for at in range(0, len(values), 8):
        chunk = ", ".join(f"0x{value:08x}" for value in values[at : at + 8])
        suffix = "," if at + 8 < len(values) else ""
        lines.append(f"    {chunk}{suffix}")
    lines.append("];")
    return lines


def table_case(
    tables: dict[str, list[int]], family: str, major: int, minor: int
) -> str | None:
    name = f"inat_{family}_table_{major}"
    if minor:
        name += f"_{minor}"
    return name if name in tables else None


def emit_lookup(
    tables: dict[str, list[int]], function: str, family: str, majors: range
) -> list[str]:
    lines = [f"fn {function}(major: u8, minor: u8, index: u8) -> u32, bool {{"]
    for major in majors:
        variants = [table_case(tables, family, major, minor) for minor in range(4)]
        if not any(variants):
            continue
        lines.append(f"    if major == {major} {{")
        for minor, name in enumerate(variants):
            if name is not None:
                lines.append(
                    f"        if minor == {minor} {{ return {name}[index as i64], true; }}"
                )
        lines.append("        return 0, false;")
        lines.append("    }")
    lines.append("    return 0, false;")
    lines.append("}")
    return lines


def emit_goose(source: pathlib.Path, tables: dict[str, list[int]], revision: str) -> str:
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    lines = [
        "// SPDX-License-Identifier: GPL-2.0-or-later",
        "//",
        "// Generated by tools/gen-x86-tables.py from Linux inat-tables.c.",
        f"// Linux revision: {revision}",
        f"// Source SHA-256: {digest}",
        "// Do not edit by hand.",
        "namespace x86_tables;",
        "",
    ]
    for name, values in tables.items():
        lines.extend(emit_array(name, values))
        lines.append("")

    lines.extend(
        [
            "fn primary(index: u8) -> u32 {",
            "    inat_primary_table[index as i64]",
            "}",
            "",
        ]
    )
    lines.extend(emit_lookup(tables, "escape_raw", "escape", range(1, 4)))
    lines.append("")
    lines.extend(emit_lookup(tables, "group_raw", "group", range(1, 32)))
    lines.append("")

    # AVX maps 1..3 alias the corresponding legacy escape maps.
    lines.append("fn avx_raw(major: u8, minor: u8, index: u8) -> u32, bool {")
    lines.append("    if major >= 1 && major <= 3 {")
    lines.append("        return escape_raw(major, minor, index);")
    lines.append("    }")
    for major in range(4, 32):
        variants = [table_case(tables, "avx", major, minor) for minor in range(4)]
        if not any(variants):
            continue
        lines.append(f"    if major == {major} {{")
        for minor, name in enumerate(variants):
            if name is not None:
                lines.append(
                    f"        if minor == {minor} {{ return {name}[index as i64], true; }}"
                )
        lines.append("        return 0, false;")
        lines.append("    }")
    lines.append("    return 0, false;")
    lines.append("}")
    lines.append("")

    lines.append("fn xop_raw(map_select: u8, index: u8) -> u32, bool {")
    for offset in range(24):
        name = f"inat_xop_table_{offset}"
        if name in tables:
            lines.append(
                f"    if map_select == {offset + 8} {{ return {name}[index as i64], true; }}"
            )
    lines.append("    return 0, false;")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=pathlib.Path, help="generated Linux inat-tables.c")
    parser.add_argument("output", type=pathlib.Path, help="Goose output file")
    parser.add_argument("--revision", required=True, help="Linux commit used for the table")
    args = parser.parse_args()

    tables = read_tables(args.source)
    output = emit_goose(args.source, tables, args.revision)
    args.output.write_text(output)


if __name__ == "__main__":
    main()
