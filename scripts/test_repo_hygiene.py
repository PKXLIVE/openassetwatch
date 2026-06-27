from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"

EXPECTED_README_DIRS = (
    ".github/",
    "backend/",
    "collector/",
    "cmd/",
    "configs/",
    "database/",
    "docs/",
    "frontend/",
    "installers/",
    "internal/",
    "packaging/",
    "pkg/",
    "scripts/",
    "web/",
)

UNSAFE_WORKFLOW_TERMS = (
    "active scan",
    "active scanning",
    "command execution",
    "credential collection",
    "exploit execution",
    "exploit payload",
    "payload generator",
    "remote command execution",
    "self-update execution",
    "webshell",
)

DEFENSIVE_CONTEXT_MARKERS = (
    "avoid",
    "blocked",
    "disabled",
    "do not",
    "does not",
    "fail if",
    "must not",
    "no ",
    "not ",
    "out of scope",
    "approval",
    "prohibit",
    "refuse",
    "reject",
    "unavailable",
    "without",
)

APPROVED_POLICY_OR_TEST_PATHS = (
    "docs/SECURITY_TOOL_POLICY.md",
    "docs/legacy-source-review/",
    "collector/openassetwatch_collector/main.py",
    "scripts/seed_control_tower_demo.py",
    "scripts/test_",
    "backend/tests/",
    "collector/tests/",
    "tests/",
)

SKIPPED_PATH_PARTS = (
    "/dist/",
    "/__pycache__/",
    "/.git/",
    "/.venv/",
    "/.wix/",
)


def _legacy_source_terms() -> tuple[str, ...]:
    encoded_terms = (
        (65, 105, 83, 79, 67),
        (97, 105, 115, 111, 99),
        (116, 114, 121, 97, 105, 115, 111, 99),
        (98, 101, 101, 110, 117, 97, 114),
        (103, 104, 99, 114, 46, 105, 111, 47, 98, 101, 101, 110, 117, 97, 114),
    )
    return tuple("".join(chr(codepoint) for codepoint in term).lower() for term in encoded_terms)


def _malformed_project_names() -> tuple[str, ...]:
    encoded_names = (
        (79, 112, 101, 110, 32, 65, 115, 115, 101, 116, 32, 87, 97, 116, 99, 104),
        (79, 112, 101, 110, 65, 115, 115, 101, 116, 32, 87, 97, 116, 99, 104),
        (79, 112, 101, 110, 32, 65, 115, 115, 101, 116, 87, 97, 116, 99, 104),
        (111, 112, 101, 110, 97, 115, 115, 101, 116, 32, 119, 97, 116, 99, 104),
    )
    return tuple("".join(chr(codepoint) for codepoint in name) for name in encoded_names)


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    files: list[Path] = []
    for line in result.stdout.splitlines():
        rel = line.replace("\\", "/")
        if any(part in f"/{rel}" for part in SKIPPED_PATH_PARTS):
            continue
        files.append(REPO_ROOT / rel)
    return files


def text_for(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="ignore")


def rel_path(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def approved_policy_or_test(path: str) -> bool:
    return any(path == prefix or path.startswith(prefix) for prefix in APPROVED_POLICY_OR_TEST_PATHS)


def defensive_context(line: str) -> bool:
    lower_line = line.lower()
    return any(marker in lower_line for marker in DEFENSIVE_CONTEXT_MARKERS)


class RepoHygieneTests(unittest.TestCase):
    def test_readme_structure_lists_current_key_directories(self) -> None:
        readme = README.read_text(encoding="utf-8")
        for directory in EXPECTED_README_DIRS:
            with self.subTest(directory=directory):
                self.assertIn(directory, readme)

    def test_frontend_placeholder_points_to_current_dashboard_location(self) -> None:
        frontend_readme = (REPO_ROOT / "frontend" / "README.md").read_text(encoding="utf-8")
        self.assertIn("reserved for future OpenAssetWatch frontend experiments", frontend_readme)
        self.assertIn("backend/app/static/", frontend_readme)
        self.assertIn("web/", frontend_readme)

    def test_no_legacy_source_branding_in_tracked_text(self) -> None:
        disallowed = _legacy_source_terms()
        failures: list[str] = []
        for path in tracked_files():
            text = text_for(path)
            if text is None:
                continue
            lower_text = text.lower()
            for term in disallowed:
                if term in lower_text:
                    failures.append(f"{rel_path(path)} contains legacy/source branding")
        self.assertEqual([], failures)

    def test_openassetwatch_name_is_not_malformed(self) -> None:
        malformed_names = _malformed_project_names()
        failures: list[str] = []
        for path in tracked_files():
            text = text_for(path)
            if text is None:
                continue
            for name in malformed_names:
                if name in text:
                    failures.append(f"{rel_path(path)} contains malformed name {name!r}")
        self.assertEqual([], failures)

    def test_unsafe_workflow_terms_are_policy_or_defensive_context_only(self) -> None:
        failures: list[str] = []
        for path in tracked_files():
            rel = rel_path(path)
            text = text_for(path)
            if text is None:
                continue
            lines = text.splitlines()
            for line_number, line in enumerate(lines, start=1):
                lower_line = line.lower()
                if not any(term in lower_line for term in UNSAFE_WORKFLOW_TERMS):
                    continue
                context = "\n".join(lines[max(0, line_number - 10) : min(len(lines), line_number + 1)])
                if approved_policy_or_test(rel) or defensive_context(context):
                    continue
                failures.append(f"{rel}:{line_number}: {line.strip()}")
        self.assertEqual([], failures)


if __name__ == "__main__":
    sys.exit(unittest.main())
