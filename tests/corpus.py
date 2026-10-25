#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Run gobjtool's checked ELF reader over an existing kernel object corpus."""

from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path


if len(sys.argv) != 3:
    raise SystemExit("usage: corpus.py GOBJTOOL KERNEL_BUILD_DIR")

gobjtool = Path(sys.argv[1]).resolve()
build_dir = Path(sys.argv[2]).resolve()
checked = 0
skipped = 0
failures: list[tuple[Path, str]] = []

for obj in sorted(build_dir.rglob("*.o")):
    try:
        with obj.open("rb") as stream:
            header = stream.read(20)
    except OSError as error:
        failures.append((obj, str(error)))
        continue
    if (len(header) < 20 or header[:7] != b"\x7fELF\x02\x01\x01" or
            struct.unpack_from("<H", header, 16)[0] != 1 or
            struct.unpack_from("<H", header, 18)[0] != 62):
        skipped += 1
        continue
    result = subprocess.run(
        [gobjtool, "check", obj],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode:
        failures.append((obj, result.stderr.strip()))
    else:
        checked += 1

for path, diagnostic in failures:
    print(f"FAIL {path}: {diagnostic}", file=sys.stderr)
print(f"kernel corpus: checked={checked} skipped={skipped} failed={len(failures)}")
raise SystemExit(bool(failures))
