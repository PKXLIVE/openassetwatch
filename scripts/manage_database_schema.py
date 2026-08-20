#!/usr/bin/env python3
"""Operator-only status, verification, and forward migration commands."""

from __future__ import annotations

import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPOSITORY_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.schema_migrations import operator_main  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    return operator_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
