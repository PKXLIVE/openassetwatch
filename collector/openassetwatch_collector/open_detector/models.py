"""Models and detector interfaces for open_detector."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from .platform import PlatformContext


@dataclass(frozen=True)
class DetectorResult:
    """Normalized passive software detection result."""

    name: str
    category: str
    detected: bool
    evidence: list[str] = field(default_factory=list)
    confidence: str = "low"
    scope: str = "system"
    source: str = "path"
    version: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "category": self.category,
            "detected": self.detected,
            "version": self.version,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "scope": self.scope,
            "source": self.source,
        }


class Detector(Protocol):
    """Protocol implemented by passive local software detectors."""

    name: str
    category: str

    def detect(self, platform: PlatformContext) -> DetectorResult:
        """Return a normalized detection result for the current host."""
