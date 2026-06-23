#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
errors: list[str] = []


def fail(message: str) -> None:
    errors.append(message)


def read_text(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def tracked_files() -> list[pathlib.Path]:
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=ROOT,
            capture_output=True,
            check=True,
            text=True,
        )
        return [ROOT / line.strip() for line in result.stdout.splitlines() if line.strip()]
    except Exception:
        ignored_dirs = {".git", "dist", "__pycache__", ".venv", "venv", "node_modules"}
        return [
            path
            for path in ROOT.rglob("*")
            if path.is_file() and not any(part in ignored_dirs for part in path.parts)
        ]


def contains_legacy_brand(text: str) -> bool:
    return re.search("ai" + "soc", text, re.IGNORECASE) is not None


license_file = ROOT / "LICENSE"
notice_file = ROOT / "NOTICE"
readme_file = ROOT / "README.md"
package_json = ROOT / "package.json"
linux_packaging_file = ROOT / "scripts" / "release" / "linux_packaging.py"
rpm_spec_template = ROOT / "packaging" / "agent" / "linux" / "rpm" / "openassetwatch-agent.spec.in"

readme_license_statement = (
    "OpenAssetWatch is licensed under the Apache License, Version 2.0. "
    "See LICENSE for details."
)
license_ref_placeholder = "LicenseRef-" + "OpenAssetWatch-" + "UNSPECIFIED"

if not license_file.exists():
    fail("Missing OpenAssetWatch root LICENSE file.")
else:
    text = read_text(license_file)
    if not text.lstrip().startswith("Apache License") or "Version 2.0, January 2004" not in text:
        fail("OpenAssetWatch LICENSE must contain canonical Apache License 2.0 text.")

if not notice_file.exists():
    fail("Missing OpenAssetWatch NOTICE file.")
else:
    notice = read_text(notice_file)
    if "OpenAssetWatch" not in notice or "OpenAssetWatch contributors" not in notice:
        fail("NOTICE must identify OpenAssetWatch and OpenAssetWatch contributors.")

if not readme_file.exists():
    fail("Missing README.md.")
else:
    readme = read_text(readme_file)
    if "## License" not in readme:
        fail("README.md is missing a License section.")
    if readme_license_statement not in readme:
        fail("README.md must contain the canonical Apache-2.0 license statement.")

if package_json.exists():
    data = json.loads(read_text(package_json))
    if data.get("license") != "Apache-2.0":
        fail("package.json license must be Apache-2.0.")
    if contains_legacy_brand(json.dumps(data, sort_keys=True)):
        fail("package.json contains legacy project branding; replace it with OpenAssetWatch.")

if not linux_packaging_file.exists():
    fail("scripts/release/linux_packaging.py is missing.")
else:
    linux_packaging_text = read_text(linux_packaging_file)
    if 'PACKAGE_LICENSE = "Apache-2.0"' not in linux_packaging_text:
        fail("scripts/release/linux_packaging.py must set PACKAGE_LICENSE to Apache-2.0.")

if not rpm_spec_template.exists():
    fail("RPM spec template is missing.")
else:
    spec_text = read_text(rpm_spec_template)
    if "License: {{PACKAGE_LICENSE}}" not in spec_text:
        fail("RPM spec template must declare License from PACKAGE_LICENSE.")
    if "%license /usr/share/doc/openassetwatch-agent/LICENSE" not in spec_text:
        fail("RPM spec template must mark the packaged LICENSE with %license.")
    if "%doc /usr/share/doc/openassetwatch-agent/NOTICE" not in spec_text:
        fail("RPM spec template must package NOTICE as documentation.")

scan_extensions = {
    ".go",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".sh",
    ".spec",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}

old_license_phrases = [
    "MI" + "T License",
    "MI" + "T-licensed",
    "under " + "MI" + "T",
]

auth_word = "authoritative"
l_word = "license"
r_word = "release"
b_word = "blocked"
info_word = "information"

blocked_license_phrases = [
    " ".join((auth_word, l_word, "declaration")),
    " ".join(("lacks", "an", auth_word, l_word)),
    " ".join(("no", auth_word, l_word, "exists")),
    " ".join((r_word, "remains", b_word, "until")),
    " ".join((r_word, "is", b_word, "for", "lack", "of", l_word)),
    " ".join((l_word, info_word, "will", "be", "added", "later")),
    " ".join((l_word.capitalize(), info_word, "will", "be", "added", "as", "the", "project", "matures")),
]

for path in tracked_files():
    if path.suffix not in scan_extensions:
        continue
    if not path.exists():
        continue
    rel = path.relative_to(ROOT)
    text = read_text(path)

    if contains_legacy_brand(text):
        fail(f"{rel} contains legacy project branding; replace it with OpenAssetWatch.")

    if license_ref_placeholder in text:
        fail(f"{rel} still contains the old OpenAssetWatch license placeholder.")

    for phrase in old_license_phrases:
        if re.search(re.escape(phrase), text, re.IGNORECASE):
            fail(f"{rel} contains old project-license wording; OpenAssetWatch should use Apache-2.0.")

    lowered = text.lower()
    for phrase in blocked_license_phrases:
        if phrase.lower() in lowered:
            fail(f"{rel} still contains pre-license placeholder wording.")

if errors:
    print("OpenAssetWatch license metadata check failed:")
    for error in errors:
        print(f" - {error}")
    sys.exit(1)

print("OpenAssetWatch license metadata check passed.")
