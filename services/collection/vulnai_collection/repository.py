"""Repositórios de achado (`Finding`) e catálogo de vulnerabilidade (`Vulnerability`).

`Vulnerability` não carrega `client_id` — é um catálogo compartilhado entre tenants
(um CVE é o mesmo CVE para todo mundo). `Finding` é por tenant e funde por identidade
natural em rescans, preservando o que a triagem humana já decidiu: um rescan que
redetecta o mesmo problema não deve reverter `status=FALSE_POSITIVE` de volta para `NEW`.
"""

from __future__ import annotations

from typing import Protocol

from vulnai_shared.enums import FindingStatus
from vulnai_shared.models import Finding, Vulnerability


class FindingRepository(Protocol):
    def upsert(self, candidate: Finding) -> Finding: ...
    def set_status(
        self, finding_id: str, status: FindingStatus, *, analyst_label: FindingStatus | None = None
    ) -> Finding: ...
    def list_for_engagement(self, client_id: str, engagement_id: str) -> list[Finding]: ...


class VulnerabilityRepository(Protocol):
    def get_by_cve(self, cve_id: str) -> Vulnerability | None: ...
    def upsert(self, candidate: Vulnerability) -> Vulnerability: ...


class InMemoryFindingRepository:
    def __init__(self) -> None:
        self._by_id: dict[str, Finding] = {}
        self._index: dict[tuple[str, str, str | None, str | None, str], str] = {}

    def upsert(self, candidate: Finding) -> Finding:
        key = (
            candidate.client_id,
            candidate.asset_id,
            candidate.service_id,
            candidate.vulnerability_id,
            candidate.title,
        )
        existing_id = self._index.get(key)
        if existing_id is not None:
            existing = self._by_id[existing_id]
            merged = existing.model_copy(
                update={
                    "severity": candidate.severity,
                    "evidence": candidate.evidence,
                    "source_tool": candidate.source_tool,
                    # status e analyst_label não são sobrescritos: triagem humana
                    # sobrevive a um rescan que redetecta o mesmo achado.
                }
            )
            self._by_id[merged.id] = merged
            return merged

        self._by_id[candidate.id] = candidate
        self._index[key] = candidate.id
        return candidate

    def set_status(
        self, finding_id: str, status: FindingStatus, *, analyst_label: FindingStatus | None = None
    ) -> Finding:
        """Triagem humana. Único caminho que muda `status`/`analyst_label` — `upsert`
        (chamado por scanners) nunca toca esses campos, de propósito."""
        existing = self._by_id.get(finding_id)
        if existing is None:
            raise KeyError(f"finding {finding_id!r} não existe")
        updated = existing.model_copy(
            update={"status": status, "analyst_label": analyst_label or status}
        )
        self._by_id[updated.id] = updated
        return updated

    def list_for_engagement(self, client_id: str, engagement_id: str) -> list[Finding]:
        return [
            f
            for f in self._by_id.values()
            if f.client_id == client_id and f.engagement_id == engagement_id
        ]


class InMemoryVulnerabilityRepository:
    def __init__(self) -> None:
        self._by_cve: dict[str, Vulnerability] = {}

    def get_by_cve(self, cve_id: str) -> Vulnerability | None:
        return self._by_cve.get(cve_id)

    def upsert(self, candidate: Vulnerability) -> Vulnerability:
        if candidate.cve_id is None:
            return candidate

        existing = self._by_cve.get(candidate.cve_id)
        if existing is not None:
            merged = existing.model_copy(
                update={
                    "cvss_score": candidate.cvss_score if candidate.cvss_score is not None else existing.cvss_score,
                    "cvss_vector": candidate.cvss_vector or existing.cvss_vector,
                    "description": candidate.description or existing.description,
                    "in_cisa_kev": candidate.in_cisa_kev or existing.in_cisa_kev,
                    "references": tuple(sorted(set(existing.references) | set(candidate.references))),
                    "published_at": candidate.published_at or existing.published_at,
                }
            )
            self._by_cve[candidate.cve_id] = merged
            return merged

        self._by_cve[candidate.cve_id] = candidate
        return candidate
