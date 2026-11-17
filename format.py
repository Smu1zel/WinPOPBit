#!/usr/bin/env python3
"""Format WinPOPBit's Python sources with Ruff.

Runs ``ruff format`` over:
  - Python files in the repository root
  - the ``debug/`` directory
  - the ``src/`` directory
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def collect_targets() -> list[str]:
    targets: list[str] = []

    # Top-level Python files in the repository root.
    for path in sorted(ROOT.glob("*.py")):
        targets.append(str(path))

    # Recursively formatted directories.
    for directory in ("debug", "src"):
        directory_path = ROOT / directory
        if directory_path.is_dir():
            targets.append(str(directory_path))

    return targets


def main() -> int:
    targets = collect_targets()
    if not targets:
        print("No Python files found to format.", file=sys.stderr)
        return 0

    command = ["ruff", "format", *targets]
    print("Running:", " ".join(command))
    result = subprocess.run(command, cwd=ROOT)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
