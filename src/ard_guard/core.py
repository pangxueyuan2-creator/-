"""Deterministic, dependency-free policy checks for discovered agentic resources."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any, Iterable


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_WEIGHTS = {
    Severity.LOW: 2,
    Severity.MEDIUM: 8,
    Severity.HIGH: 20,
    Severity.CRITICAL: 40,
}


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: Severity
    path: str
    message: str
    evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass(frozen=True, slots=True)
class ScanReport:
    findings: tuple[Finding, ...]

    @property
    def risk_score(self) -> int:
        return min(100, sum(_WEIGHTS[f.severity] for f in self.findings))

    @property
    def highest_severity(self) -> Severity | None:
        if not self.findings:
            return None
        order = {
            Severity.LOW: 0,
            Severity.MEDIUM: 1,
            Severity.HIGH: 2,
            Severity.CRITICAL: 3,
        }
        return max((f.severity for f in self.findings), key=order.__getitem__)

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "highest_severity": self.highest_severity.value if self.highest_severity else None,
            "finding_count": len(self.findings),
            "findings": [finding.to_dict() for finding in self.findings],
        }


_PIPE_TO_SHELL = re.compile(
    r"(?is)\b(?:curl|wget|iwr|invoke-webrequest)\b.{0,300}\|\s*"
    r"(?:sh|bash|zsh|fish|iex|invoke-expression)\b"
)
_MUTABLE_GITHUB_REF = re.compile(
    r"(?i)https?://(?:raw\.)?github(?:usercontent)?\.com/[^\s'\"<>]+/"
    r"(?:blob/|tree/)?(?:main|master|head|latest)(?:/|\b)"
)
_UNPINNED_PACKAGE = re.compile(
    r"(?i)(?:^|[;&|]\s*)(?:sudo\s+)?(?:python\s+-m\s+)?pip\s+install\s+(?![^\n;&|]*==)"
    r"|(?:^|[;&|]\s*)(?:sudo\s+)?npm\s+(?:install|i)\s+(?![^\n;&|]*@\d)"
    r"|(?:^|[;&|]\s*)(?:sudo\s+)?(?:npx|uvx)\s+(?![^\n;&|]*@\d)"
)
_PRIVILEGED = re.compile(
    r"(?i)(?:\bsudo\b|--privileged\b|/var/run/docker\.sock|docker\.sock|"
    r"chmod\s+(?:-R\s+)?777\b|\bsetcap\b|\bchown\s+-R\b)"
)
_SECRET_HARVEST = re.compile(
    r"(?i)(?:printenv|\benv\b|set)\s*(?:\||>|>>).{0,120}(?:curl|wget|http)"
    r"|(?:curl|wget).{0,180}(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD)"
)

_RESOURCE_ENDPOINT_KEYS = {
    "url",
    "uri",
    "endpoint",
    "source",
    "repository",
    "repository_url",
    "homepage",
    "download_url",
}
_RESOURCE_NAME_KEYS = {"name", "title", "id"}
_IDENTITY_KEYS = {"publisher", "operator", "owner", "provider", "organization", "author"}


def _path(parent: str, key: str | int) -> str:
    if isinstance(key, int):
        return f"{parent}[{key}]"
    return f"{parent}.{key}" if parent != "$" else f"$.{key}"


def _walk(value: Any, parent: str = "$") -> Iterable[tuple[str, Any]]:
    yield parent, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk(child, _path(parent, str(key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, _path(parent, index))


def _short(text: str, limit: int = 180) -> str:
    compact = " ".join(text.split())
    return compact if len(compact) <= limit else compact[: limit - 1] + "…"


def _string_findings(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lowered = text.lower()

    if "http://" in lowered:
        findings.append(
            Finding(
                "AG001",
                Severity.HIGH,
                path,
                "Insecure HTTP transport can allow resource or metadata tampering.",
                _short(text),
            )
        )

    if _MUTABLE_GITHUB_REF.search(text):
        findings.append(
            Finding(
                "AG002",
                Severity.HIGH,
                path,
                "GitHub source points at a mutable ref; pin an immutable commit or release artifact.",
                _short(text),
            )
        )

    if _PIPE_TO_SHELL.search(text):
        findings.append(
            Finding(
                "AG003",
                Severity.CRITICAL,
                path,
                "Remote content is piped directly into a shell interpreter.",
                _short(text),
            )
        )

    if _UNPINNED_PACKAGE.search(text):
        findings.append(
            Finding(
                "AG004",
                Severity.MEDIUM,
                path,
                "Package installation appears unpinned and may resolve different code over time.",
                _short(text),
            )
        )

    if _PRIVILEGED.search(text):
        findings.append(
            Finding(
                "AG005",
                Severity.HIGH,
                path,
                "Instruction or configuration requests elevated host/container privileges.",
                _short(text),
            )
        )

    if _SECRET_HARVEST.search(text):
        findings.append(
            Finding(
                "AG006",
                Severity.CRITICAL,
                path,
                "Command pattern may collect environment secrets and transmit them externally.",
                _short(text),
            )
        )

    return findings


def _resource_findings(path: str, obj: dict[str, Any]) -> list[Finding]:
    keys = {str(key).lower() for key in obj}
    looks_like_resource = bool(keys & _RESOURCE_NAME_KEYS) and bool(keys & _RESOURCE_ENDPOINT_KEYS)
    if not looks_like_resource:
        return []

    findings: list[Finding] = []
    if not keys & _IDENTITY_KEYS:
        findings.append(
            Finding(
                "AG007",
                Severity.MEDIUM,
                path,
                "Resource-like entry has no explicit publisher/operator identity metadata.",
            )
        )

    provenance_keys = {"source", "repository", "repository_url", "provenance", "digest", "sha256"}
    if not keys & provenance_keys:
        findings.append(
            Finding(
                "AG008",
                Severity.MEDIUM,
                path,
                "Resource-like entry has no source repository, provenance, or digest metadata.",
            )
        )

    return findings


def scan_document(document: Any) -> ScanReport:
    """Scan a decoded JSON-compatible document and return deterministic findings."""

    findings: list[Finding] = []
    for path, value in _walk(document):
        if isinstance(value, str):
            findings.extend(_string_findings(path, value))
        elif isinstance(value, dict):
            findings.extend(_resource_findings(path, value))

    # Stable output keeps CI diffs and downstream policy decisions reproducible.
    unique = {
        (f.rule_id, f.severity.value, f.path, f.message, f.evidence): f for f in findings
    }
    ordered = sorted(unique.values(), key=lambda f: (f.path, f.rule_id, f.message))
    return ScanReport(tuple(ordered))
