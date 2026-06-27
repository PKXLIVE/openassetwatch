from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
BACKEND_DOCKERFILE = REPO_ROOT / "backend" / "Dockerfile"
DOC_FILES = [
    REPO_ROOT / "README.md",
    REPO_ROOT / "backend" / "README.md",
    REPO_ROOT / "web" / "README.md",
    REPO_ROOT / "docs" / "CONTROL_TOWER_DEPLOYMENT.md",
]


class ControlTowerComposeReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compose_text = COMPOSE_FILE.read_text(encoding="utf-8")

    def test_postgres_backend_and_web_healthchecks_exist(self) -> None:
        self.assertIn("pg_isready -U openassetwatch -d openassetwatch", self.compose_text)
        self.assertIn("urllib.request.urlopen('http://127.0.0.1:8000/health'", self.compose_text)
        self.assertIn("wget -q -O /dev/null http://127.0.0.1/", self.compose_text)

    def test_health_aware_dependency_ordering(self) -> None:
        self.assertRegex(
            self.compose_text,
            r"(?s)backend:\s+build:.*?depends_on:\s+postgres:\s+condition: service_healthy",
        )
        self.assertRegex(
            self.compose_text,
            r"(?s)web:\s+image: nginx:1\.27-alpine.*?depends_on:\s+backend:\s+condition: service_healthy",
        )

    def test_backend_dependencies_install_at_image_build_time(self) -> None:
        dockerfile = BACKEND_DOCKERFILE.read_text(encoding="utf-8")

        self.assertIn("context: ./backend", self.compose_text)
        self.assertIn("openassetwatch-control-tower-backend:local", self.compose_text)
        self.assertNotRegex(self.compose_text, r"(?i)pip\s+install")
        self.assertIn("RUN pip install --no-cache-dir -r /tmp/openassetwatch-requirements.txt", dockerfile)

    def test_host_ports_are_localhost_only(self) -> None:
        self.assertIn('"127.0.0.1:5432:5432"', self.compose_text)
        self.assertIn('"127.0.0.1:8000:8000"', self.compose_text)
        self.assertIn('"127.0.0.1:8080:80"', self.compose_text)
        self.assertNotRegex(self.compose_text, r'(?m)^\s+-\s+"?(?:0\.0\.0\.0:)?(?:5432|6379|8000|8080):')

    def test_redis_is_not_retained_without_mvp_usage(self) -> None:
        self.assertNotRegex(self.compose_text, r"(?m)^\s{2}redis:")
        self.assertNotIn("openassetwatch-redis", self.compose_text)
        requirements = (REPO_ROOT / "backend" / "requirements.txt").read_text(encoding="utf-8")
        self.assertNotRegex(requirements, r"(?m)^redis\b")

    def test_demo_seed_service_uses_backend_image_and_profile(self) -> None:
        self.assertRegex(
            self.compose_text,
            r"(?s)demo-seed:\s+profiles: \[\"demo\"\].*?image: openassetwatch-control-tower-backend:local",
        )
        self.assertIn("OPENASSETWATCH_DEMO_SEED_ALLOW_COMPOSE_HOST: \"1\"", self.compose_text)
        self.assertIn("scripts/seed_control_tower_demo.py", self.compose_text)
        self.assertIn("--allow-compose-database-host", self.compose_text)
        self.assertRegex(
            self.compose_text,
            r"(?s)demo-seed:.*?depends_on:\s+postgres:\s+condition: service_healthy",
        )

    def test_docs_match_compose_readiness(self) -> None:
        for path in DOC_FILES:
            with self.subTest(path=path):
                content = path.read_text(encoding="utf-8")
                self.assertIn("localhost", content)
        deployment_doc = (REPO_ROOT / "docs" / "CONTROL_TOWER_DEPLOYMENT.md").read_text(encoding="utf-8")
        self.assertIn("Redis is not part of the current Control Tower MVP stack", deployment_doc)

    def test_no_legacy_branding_or_disallowed_images(self) -> None:
        checked_paths = [COMPOSE_FILE, *DOC_FILES, REPO_ROOT / "backend" / "Dockerfile"]
        disallowed_markers = (
            "".join(chr(value) for value in (65, 105, 83, 79, 67)),
            "".join(chr(value) for value in (98, 101, 101, 110, 117, 97, 114)),
            "".join(chr(value) for value in (116, 114, 121, 97, 105, 115, 111, 99)),
            "".join(
                chr(value)
                for value in (
                    103,
                    104,
                    99,
                    114,
                    46,
                    105,
                    111,
                    47,
                    98,
                    101,
                    101,
                    110,
                    117,
                    97,
                    114,
                )
            ),
        )
        for path in checked_paths:
            with self.subTest(path=path):
                content = path.read_text(encoding="utf-8")
                for marker in disallowed_markers:
                    self.assertNotIn(marker, content)


if __name__ == "__main__":
    unittest.main()
