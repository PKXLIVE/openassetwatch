"""Passive local software detectors used by open_detector."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import DetectorResult
from .platform import PlatformContext


@dataclass(frozen=True)
class SoftwareDetector:
    """Generic evidence-based detector for known local tools."""

    name: str
    category: str
    commands: tuple[str, ...] = ()
    paths_by_system: dict[str, tuple[str, ...]] = field(default_factory=dict)
    version_commands: tuple[tuple[str, ...], ...] = ()
    scope: str = "system"
    path_confidence: str = "medium"

    def detect(self, platform: PlatformContext) -> DetectorResult:
        evidence: list[str] = []
        source = "path"
        version = None

        for command in self.commands:
            if platform.command_exists(command):
                evidence.append(f"command_found:{command}")
                source = "command"

        for path in self.paths_by_system.get(platform.system_key, ()):
            if platform.path_exists(path):
                evidence.append(f"path_exists:{path}")

        if evidence:
            for version_command in self.version_commands:
                version = platform.version_output(list(version_command))
                if version:
                    evidence.append(f"version_output:{version_command[0]}")
                    break

        return DetectorResult(
            name=self.name,
            category=self.category,
            detected=bool(evidence),
            version=version,
            evidence=evidence,
            confidence=self._confidence(evidence, version),
            scope=self.scope,
            source=source if any(item.startswith("command_found:") for item in evidence) else "path",
        )

    def _confidence(self, evidence: list[str], version: str | None) -> str:
        if not evidence:
            return "none"
        if version or len(evidence) > 1:
            return "high"
        if any(item.startswith("command_found:") for item in evidence):
            return "medium"
        return self.path_confidence


DETECTORS = [
    SoftwareDetector(
        name="Splunk Universal Forwarder",
        category="log_forwarder",
        commands=("splunk", "splunk.exe"),
        paths_by_system={
            "windows": (
                r"%ProgramFiles%\SplunkUniversalForwarder\bin\splunk.exe",
                r"%ProgramFiles(x86)%\SplunkUniversalForwarder\bin\splunk.exe",
            ),
            "linux": ("/opt/splunkforwarder/bin/splunk",),
            "darwin": ("/Applications/SplunkForwarder/bin/splunk",),
        },
    ),
    SoftwareDetector(
        name="CrowdStrike Falcon",
        category="edr",
        commands=("falconctl",),
        paths_by_system={
            "windows": (r"%ProgramFiles%\CrowdStrike\CSFalconService.exe",),
            "linux": ("/opt/CrowdStrike/falconctl",),
            "darwin": ("/Applications/Falcon.app", "/Library/CS/falconctl"),
        },
    ),
    SoftwareDetector(
        name="Microsoft Defender",
        category="edr",
        commands=("mdatp", "MpCmdRun.exe"),
        paths_by_system={
            "windows": (
                r"%ProgramFiles%\Windows Defender\MpCmdRun.exe",
                r"%ProgramData%\Microsoft\Windows Defender\Platform",
            ),
            "linux": ("/usr/bin/mdatp", "/opt/microsoft/mdatp"),
            "darwin": ("/usr/local/bin/mdatp", "/Applications/Microsoft Defender.app"),
        },
        version_commands=(("mdatp", "version"),),
    ),
    SoftwareDetector(
        name="Docker Desktop",
        category="container_runtime",
        commands=("docker",),
        paths_by_system={
            "windows": (r"%ProgramFiles%\Docker\Docker\Docker Desktop.exe",),
            "linux": ("/usr/bin/docker", "/var/run/docker.sock"),
            "darwin": ("/Applications/Docker.app",),
        },
        version_commands=(("docker", "--version"),),
    ),
    SoftwareDetector(
        name="OpenTelemetry Collector",
        category="observability",
        commands=("otelcol", "otelcol-contrib"),
        paths_by_system={
            "windows": (
                r"%ProgramFiles%\OpenTelemetry Collector\otelcol.exe",
                r"%ProgramFiles%\OpenTelemetry Collector Contrib\otelcol-contrib.exe",
            ),
            "linux": ("/usr/bin/otelcol", "/usr/local/bin/otelcol", "/opt/otelcol"),
            "darwin": ("/usr/local/bin/otelcol", "/opt/homebrew/bin/otelcol"),
        },
        version_commands=(("otelcol", "--version"), ("otelcol-contrib", "--version")),
    ),
    SoftwareDetector(
        name="Qualys Cloud Agent",
        category="vulnerability_agent",
        commands=("qualys-cloud-agent",),
        paths_by_system={
            "windows": (r"%ProgramFiles%\Qualys\QualysAgent\QualysAgent.exe",),
            "linux": ("/usr/local/qualys/cloud-agent/bin/qualys-cloud-agent",),
            "darwin": ("/Applications/QualysCloudAgent.app", "/Library/Qualys/CloudAgent"),
        },
    ),
    SoftwareDetector(
        name="Nessus Agent",
        category="vulnerability_agent",
        commands=("nessuscli",),
        paths_by_system={
            "windows": (r"%ProgramFiles%\Tenable\Nessus Agent\nessuscli.exe",),
            "linux": ("/opt/nessus_agent/sbin/nessuscli",),
            "darwin": ("/Library/NessusAgent/run/sbin/nessuscli",),
        },
        version_commands=(("nessuscli", "--version"),),
    ),
    SoftwareDetector(
        name="Workspace ONE",
        category="mdm",
        paths_by_system={
            "windows": (r"%ProgramFiles(x86)%\AirWatch", r"%ProgramFiles%\AirWatch"),
            "darwin": ("/Applications/Workspace ONE Intelligent Hub.app",),
        },
        path_confidence="low",
    ),
    SoftwareDetector(
        name="Intune Company Portal",
        category="mdm",
        commands=("CompanyPortal.exe",),
        paths_by_system={
            "darwin": ("/Applications/Company Portal.app",),
        },
        path_confidence="low",
    ),
    SoftwareDetector(
        name="Zscaler",
        category="vpn_or_ztna",
        commands=("ZSATunnel", "zscli"),
        paths_by_system={
            "windows": (r"%ProgramFiles%\Zscaler", r"%ProgramFiles(x86)%\Zscaler"),
            "linux": ("/opt/zscaler",),
            "darwin": ("/Applications/Zscaler.app",),
        },
        path_confidence="low",
    ),
]
