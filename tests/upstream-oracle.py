#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Compare gobjtool with upstream objtool without modifying corpus objects."""

from __future__ import annotations

import argparse
import hashlib
import os
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ORC_SECTIONS = (
    ".orc_unwind",
    ".orc_unwind_ip",
    ".rela.orc_unwind_ip",
)


@dataclass(frozen=True)
class Run:
    returncode: int
    stdout: str
    stderr: str


def executable(value: str, label: str) -> Path:
    candidate = Path(value).expanduser()
    if candidate.parent != Path(".") or candidate.is_absolute():
        candidate = candidate.resolve()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    else:
        found = shutil.which(value)
        if found:
            return Path(found).resolve()
    raise SystemExit(f"oracle: {label} executable not found: {value}")


def command(binary: Path, arguments: list[str], obj: Path) -> Run:
    result = subprocess.run(
        [str(binary), *arguments, str(obj)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return Run(result.returncode, result.stdout, result.stderr)


def is_x86_64_rel(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            header = stream.read(20)
    except OSError:
        return False
    return (
        len(header) == 20
        and header[:7] == b"\x7fELF\x02\x01\x01"
        and struct.unpack_from("<H", header, 16)[0] == 1
        and struct.unpack_from("<H", header, 18)[0] == 62
    )


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def normalized(text: str, obj: Path) -> str:
    """Make diagnostics comparable across the two temporary object names."""
    value = text.replace("\r\n", "\n").replace(str(obj), "<OBJ>")
    return "\n".join(line.rstrip() for line in value.rstrip().splitlines())


def section_bytes(path: Path, wanted: tuple[str, ...]) -> dict[str, bytes]:
    """Extract raw ELF64 little-endian section payloads for ORC comparison."""
    data = path.read_bytes()
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("not a little-endian ELF64 file")
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    entry_size = struct.unpack_from("<H", data, 58)[0]
    count = struct.unpack_from("<H", data, 60)[0]
    names_index = struct.unpack_from("<H", data, 62)[0]
    if entry_size < 64 or count == 0 or names_index >= count:
        raise ValueError("unsupported or invalid ELF section table")
    table_end = section_offset + entry_size * count
    if table_end > len(data):
        raise ValueError("truncated ELF section table")

    def header(index: int) -> tuple[int, int, int]:
        at = section_offset + entry_size * index
        name = struct.unpack_from("<I", data, at)[0]
        offset = struct.unpack_from("<Q", data, at + 24)[0]
        size = struct.unpack_from("<Q", data, at + 32)[0]
        if offset + size > len(data):
            raise ValueError("section lies outside the file")
        return name, offset, size

    _, strings_offset, strings_size = header(names_index)
    strings = data[strings_offset : strings_offset + strings_size]
    result: dict[str, bytes] = {}
    for index in range(count):
        name_at, offset, size = header(index)
        if name_at >= len(strings):
            raise ValueError("invalid section name")
        end = strings.find(b"\0", name_at)
        if end < 0:
            raise ValueError("unterminated section name")
        name = strings[name_at:end].decode("utf-8", errors="surrogateescape")
        if name in wanted:
            result[name] = data[offset : offset + size]
    return result


def report_run(label: str, obj: Path, run: Run) -> None:
    print(f"{label}: {obj}: exit={run.returncode}", file=sys.stderr)
    if run.stdout:
        print(normalized(run.stdout, obj), file=sys.stderr)
    if run.stderr:
        print(normalized(run.stderr, obj), file=sys.stderr)


def parser() -> argparse.ArgumentParser:
    default_gobjtool = os.environ.get("GOBJTOOL", str(ROOT / "build/gobjtool"))
    result = argparse.ArgumentParser(
        description=(
            "Run native gobjtool and upstream objtool over an x86-64 ET_REL "
            "corpus while preserving every source object"
        )
    )
    result.add_argument("corpus", nargs="?", default=os.environ.get("CORPUS"))
    result.add_argument("--gobjtool", default=default_gobjtool)
    result.add_argument("--objtool", default=os.environ.get("OBJTOOL", "objtool"))
    result.add_argument("--pattern", default="*.o")
    result.add_argument("--limit", type=int, default=0)
    result.add_argument(
        "--mode",
        choices=("reader", "parity", "orc"),
        default="reader",
        help=(
            "reader: require gobjtool's ELF reader and record upstream results; "
            "parity: match status and diagnostics; orc: mutate temporary copies "
            "and compare ORC sections"
        ),
    )
    result.add_argument(
        "--objtool-args",
        default=os.environ.get("OBJTOOL_ARGS", "--stackval --orc"),
        help="shell-style upstream arguments (the harness adds --dry-run outside ORC mode)",
    )
    result.add_argument(
        "--gobjtool-args",
        default=os.environ.get("GOBJTOOL_ARGS", "check"),
        help="shell-style gobjtool arguments used in reader/parity mode",
    )
    result.add_argument(
        "--gobjtool-orc-args",
        default=os.environ.get("GOBJTOOL_ORC_ARGS", ""),
        help="future writer arguments for ORC mode; required there",
    )
    result.add_argument(
        "--orc-sections",
        default=",".join(DEFAULT_ORC_SECTIONS),
        help="comma-separated raw sections compared in ORC mode",
    )
    return result


def main() -> int:
    args = parser().parse_args()
    if not args.corpus:
        raise SystemExit("oracle: provide CORPUS or a corpus directory argument")
    corpus = Path(args.corpus).expanduser().resolve()
    if not corpus.is_dir():
        raise SystemExit(f"oracle: corpus directory not found: {corpus}")
    if args.limit < 0:
        raise SystemExit("oracle: --limit must not be negative")

    gobjtool = executable(args.gobjtool, "gobjtool")
    objtool = executable(args.objtool, "objtool")
    upstream_args = shlex.split(args.objtool_args)
    gobjtool_args = shlex.split(args.gobjtool_args)
    gobjtool_orc_args = shlex.split(args.gobjtool_orc_args)
    if not upstream_args:
        raise SystemExit("oracle: --objtool-args must select at least one action")
    forbidden = {"-o", "--output", "--backup"}
    if any(arg.split("=", 1)[0] in forbidden for arg in upstream_args):
        raise SystemExit("oracle: output and backup options are forbidden")
    if args.mode != "orc":
        if "--dry-run" not in upstream_args:
            upstream_args.insert(0, "--dry-run")
    elif not gobjtool_orc_args:
        raise SystemExit(
            "oracle: ORC mode is reserved until the writer exists; provide "
            "--gobjtool-orc-args (or GOBJTOOL_ORC_ARGS) when it does"
        )
    elif "--dry-run" in upstream_args or "--dry-run" in gobjtool_orc_args:
        raise SystemExit("oracle: --dry-run cannot generate sections in ORC mode")
    elif any(arg.split("=", 1)[0] in forbidden for arg in gobjtool_orc_args):
        raise SystemExit("oracle: gobjtool output and backup options are forbidden")

    objects = [path for path in sorted(corpus.rglob(args.pattern)) if is_x86_64_rel(path)]
    if args.limit:
        objects = objects[: args.limit]
    if not objects:
        raise SystemExit(f"oracle: no x86-64 ELF64 ET_REL objects under {corpus}")

    failures = 0
    upstream_diagnostics = 0
    upstream_rejected = 0
    for obj in objects:
        before = digest(obj)
        if args.mode == "orc":
            with tempfile.TemporaryDirectory(prefix="gobjtool-oracle-") as temporary:
                reference = Path(temporary) / "upstream.o"
                candidate = Path(temporary) / "gobjtool.o"
                shutil.copy2(obj, reference)
                shutil.copy2(obj, candidate)
                upstream = command(objtool, upstream_args, reference)
                native = command(gobjtool, gobjtool_orc_args, candidate)
                if upstream.returncode or native.returncode:
                    report_run("upstream", obj, upstream)
                    report_run("gobjtool", obj, native)
                    failures += 1
                else:
                    names = tuple(name for name in args.orc_sections.split(",") if name)
                    try:
                        expected = section_bytes(reference, names)
                        actual = section_bytes(candidate, names)
                    except (OSError, ValueError) as error:
                        print(f"FAIL {obj}: cannot compare ORC sections: {error}", file=sys.stderr)
                        failures += 1
                    else:
                        missing = [name for name in names if name not in expected]
                        if missing:
                            print(
                                f"FAIL {obj}: upstream did not generate: {', '.join(missing)}",
                                file=sys.stderr,
                            )
                            failures += 1
                        elif expected != actual:
                            print(f"FAIL {obj}: generated ORC sections differ", file=sys.stderr)
                            for name in names:
                                if expected.get(name) != actual.get(name):
                                    print(
                                        f"  {name}: upstream={len(expected.get(name, b''))} "
                                        f"gobjtool={len(actual.get(name, b''))}",
                                        file=sys.stderr,
                                    )
                            failures += 1
        else:
            upstream = command(objtool, upstream_args, obj)
            native = command(gobjtool, gobjtool_args, obj)
            if upstream.stderr:
                upstream_diagnostics += 1
            if upstream.returncode:
                upstream_rejected += 1
            if args.mode == "reader":
                if native.returncode:
                    report_run("upstream", obj, upstream)
                    report_run("gobjtool", obj, native)
                    failures += 1
            elif (
                upstream.returncode != native.returncode
                or normalized(upstream.stdout, obj) != normalized(native.stdout, obj)
                or normalized(upstream.stderr, obj) != normalized(native.stderr, obj)
            ):
                print(f"FAIL {obj}: status or diagnostics differ", file=sys.stderr)
                report_run("upstream", obj, upstream)
                report_run("gobjtool", obj, native)
                failures += 1
        if digest(obj) != before:
            print(f"FAIL {obj}: source object was modified", file=sys.stderr)
            failures += 1

    print(
        f"upstream oracle: mode={args.mode} checked={len(objects)} "
        f"failed={failures} upstream-rejected={upstream_rejected} "
        f"upstream-diagnostics={upstream_diagnostics}"
    )
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
