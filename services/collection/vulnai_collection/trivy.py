"""Adaptador trivy: SBOM e correlação de vulnerabilidade em imagem de contêiner."""

from __future__ import annotations

import json
from dataclasses import dataclass

from vulnai_collection.errors import ParseError


@dataclass(frozen=True, slots=True)
class TrivyVulnerability:
    cve_id: str
    pkg_name: str
    installed_version: str
    severity: str
    target: str
    fixed_version: str | None = None
    title: str | None = None


def build_command(image_ref: str, *, scanners: str = "vuln") -> list[str]:
    return ["trivy", "image", "--format", "json", "--scanners", scanners, "--quiet", image_ref]


def parse_json(text: str) -> list[TrivyVulnerability]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError("saída do trivy não é JSON válido") from exc

    vulnerabilities: list[TrivyVulnerability] = []
    for result in payload.get("Results") or ():
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities") or ():
            cve_id = vuln.get("VulnerabilityID")
            if not cve_id:
                continue
            vulnerabilities.append(
                TrivyVulnerability(
                    cve_id=cve_id,
                    pkg_name=vuln.get("PkgName", "?"),
                    installed_version=vuln.get("InstalledVersion", "?"),
                    fixed_version=vuln.get("FixedVersion"),
                    severity=vuln.get("Severity", "UNKNOWN"),
                    title=vuln.get("Title"),
                    target=target,
                )
            )
    return vulnerabilities
