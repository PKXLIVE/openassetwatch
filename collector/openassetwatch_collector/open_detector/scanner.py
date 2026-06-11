"""Scanner and registry helpers for open_detector."""

from __future__ import annotations

from .detectors import DETECTORS
from .models import Detector, DetectorResult
from .platform import PlatformContext


def registered_detectors() -> list[Detector]:
    return list(DETECTORS)


def scan(platform_info: dict[str, object] | None = None) -> list[DetectorResult]:
    platform = PlatformContext.current(platform_info)
    return [detector.detect(platform) for detector in registered_detectors()]


def scan_software(
    platform_info: dict[str, object] | None = None,
    include_not_detected: bool = False,
) -> list[dict[str, object]]:
    results = scan(platform_info)
    if not include_not_detected:
        results = [result for result in results if result.detected]
    return [result.to_dict() for result in results]
