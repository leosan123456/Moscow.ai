"""Normalização de severidade entre ferramentas de origem diferentes."""

from __future__ import annotations

from vulnai_shared.enums import Severity

_BY_LABEL: dict[str, Severity] = {
    "unknown": Severity.NONE,
    "info": Severity.NONE,
    "informational": Severity.NONE,
    "none": Severity.NONE,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def normalize(raw: str | None) -> Severity:
    """Severidade textual (nuclei, trivy, ...) → `Severity` do domínio."""
    if not raw:
        return Severity.NONE
    return _BY_LABEL.get(raw.strip().lower(), Severity.NONE)


def from_cvss(score: float | None) -> Severity:
    """Fallback quando a ferramenta não informa severidade, mas há nota CVSS v3."""
    if score is None:
        return Severity.NONE
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.NONE
