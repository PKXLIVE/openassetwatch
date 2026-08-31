#!/usr/bin/env python3
"""Require one final AGENTS.md completion review before Codex stops.

The Stop hook may continue a turn once. The subsequent Stop event reports
stop_hook_active=true, at which point this hook permits the turn to end so it
cannot create an infinite continuation loop.
"""

import json
import sys


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        print("{}")
        return 0

    if payload.get("stop_hook_active") is True:
        print("{}")
        return 0

    reason = (
        "Before stopping, perform one final OpenAssetWatch completion pass. "
        "Re-read the applicable AGENTS.md definition of done and verify the final "
        "diff, tests/validation evidence, security/privacy/licensing implications, "
        "documentation, temporary artifacts, and remaining blockers. If anything "
        "required by the assigned task is incomplete and can be completed safely "
        "within scope, continue the work and fix it now. Do not create unrelated "
        "work. If the task is complete, summarize only validation actually observed "
        "and any checks still pending."
    )
    print(json.dumps({"decision": "block", "reason": reason}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
