#!/usr/bin/env python3
"""Validate Developer Certificate of Origin sign-offs for a commit range."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass

SIGNOFF_RE = re.compile(
    r"^Signed-off-by:\s*(?P<name>.+?)\s*<(?P<email>[^<>@\s]+@[^<>\s]+)>\s*$",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass(frozen=True)
class CommitRecord:
    sha: str
    author_name: str
    author_email: str
    message: str


def git(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout


def list_commits(base: str, head: str) -> list[str]:
    output = git("rev-list", "--reverse", f"{base}..{head}")
    return [line.strip() for line in output.splitlines() if line.strip()]


def load_commit(sha: str) -> CommitRecord:
    raw = subprocess.check_output(
        ["git", "show", "-s", "--format=%H%x00%an%x00%ae%x00%B", sha]
    )
    parts = raw.decode("utf-8", errors="replace").split("\x00", 3)
    if len(parts) != 4:
        raise RuntimeError(f"Unable to parse commit metadata for {sha}")
    return CommitRecord(
        sha=parts[0].strip(),
        author_name=parts[1].strip(),
        author_email=parts[2].strip(),
        message=parts[3],
    )


def is_automation_author(record: CommitRecord) -> bool:
    name = record.author_name.casefold()
    email = record.author_email.casefold()
    return (
        name.endswith("[bot]")
        or "[bot]@" in email
        or email.endswith("@github-actions.invalid")
    )


def signoffs(message: str) -> list[tuple[str, str]]:
    return [
        (match.group("name").strip(), match.group("email").strip())
        for match in SIGNOFF_RE.finditer(message)
    ]


def validate(record: CommitRecord) -> tuple[bool, str]:
    if is_automation_author(record):
        return True, "automation author exempt"

    trailers = signoffs(record.message)
    if not trailers:
        return False, "missing Signed-off-by trailer"

    author_email = record.author_email.casefold()
    matching = [entry for entry in trailers if entry[1].casefold() == author_email]
    if not matching:
        listed = ", ".join(email for _, email in trailers)
        return (
            False,
            "Signed-off-by email does not match commit author email "
            f"({record.author_email}); found: {listed}",
        )

    return True, "valid sign-off"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate DCO Signed-off-by trailers for commits in BASE..HEAD."
    )
    parser.add_argument("--base", required=True, help="Base commit or ref")
    parser.add_argument("--head", required=True, help="Head commit or ref")
    args = parser.parse_args()

    try:
        commits = list_commits(args.base, args.head)
    except subprocess.CalledProcessError as exc:
        print(exc.stderr or str(exc), file=sys.stderr)
        return 2

    if not commits:
        print("DCO check: no commits found in the requested range.")
        return 0

    failures: list[tuple[CommitRecord, str]] = []
    exemptions = 0

    for sha in commits:
        try:
            record = load_commit(sha)
        except (subprocess.CalledProcessError, RuntimeError) as exc:
            print(f"DCO check could not inspect {sha}: {exc}", file=sys.stderr)
            return 2

        valid, reason = validate(record)
        if reason == "automation author exempt":
            exemptions += 1
        if not valid:
            failures.append((record, reason))

    if failures:
        print("DCO check failed for the following commit(s):", file=sys.stderr)
        for record, reason in failures:
            lines = record.message.splitlines()
            subject = lines[0] if lines else ""
            print(
                f"- {record.sha[:12]} {subject!r}: {reason}",
                file=sys.stderr,
            )
        print(
            "\nFix the commits with `git commit --amend --signoff` or "
            "`git rebase --signoff origin/main`, then push with "
            "`git push --force-with-lease`.",
            file=sys.stderr,
        )
        return 1

    print(
        f"DCO check passed for {len(commits)} commit(s)"
        + (f" ({exemptions} automation exemption(s))" if exemptions else "")
        + "."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
