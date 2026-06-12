from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


def load_installer_module():
    module_path = Path(__file__).resolve().parents[1] / "install" / "install.py"
    spec = importlib.util.spec_from_file_location("openassetwatch_installer", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load installer module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class InstallerTokenTests(unittest.TestCase):
    def test_redact_config_text_hides_backend_token(self) -> None:
        installer = load_installer_module()
        text = "\n".join(
            [
                "backend:",
                "  url: http://localhost:8000",
                "  token: change-me-dev-token",
                "checkin:",
                "  enabled: true",
            ]
        )

        redacted = installer.redact_config_text(text)

        self.assertIn('token: "<redacted>"', redacted)
        self.assertNotIn("change-me-dev-token", redacted)


if __name__ == "__main__":
    unittest.main()
