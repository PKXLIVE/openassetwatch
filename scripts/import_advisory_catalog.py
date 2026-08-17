#!/usr/bin/env python3
"""Deprecated unsigned advisory import entry point."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    _ = argv
    print(
        "Unsigned advisory import is disabled. Use scripts/advisory_feed_sync.py import-local with a reviewed signed source.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
