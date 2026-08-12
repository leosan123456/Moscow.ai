"""Repositórios SQL de coleta (`Finding`, `Vulnerability`)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from vulnai_shared.enums import FindingStatus
from vulnai_shared.models import Finding, Vulnerability
from vulnai_persistence.orm import FindingRow, VulnerabilityRow


class SqlFindingRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def upsert(self, candidate: Finding) -> Finding:
        with self._sessions() as session:
            row = session.scalar(
                select(FindingRow).where(
                    FindingRow.client_id == candidate.client_id,
                    FindingRow.asset_id == candidate.asset_id,
                    FindingRow.service_id == candidate.service_id,
                    FindingRow.vulnerability_id == candidate.vulnerability_id,
                    FindingRow.title == candidate.title,
                )
            )
            if row is not None:
                existing = Finding.model_validate(row.payload)
                merged = existing.model_copy(
                    update={
                        "severity": candidate.severity,
                        "evidence": candidate.evidence,
                        "source_tool": candidate.source_tool,
                        # status/analyst_label preservados: ver InMemoryFindingRepository.upsert.
                    }
                )
                row.payload = merged.model_dump(mode="json")
                session.commit()
                return merged

            session.add(
                FindingRow(
                    id=candidate.id,
                    client_id=candidate.client_id,
                    engagement_id=candidate.engagement_id,
                    asset_id=candidate.asset_id,
                    service_id=candidate.service_id,
                    vulnerability_id=candidate.vulnerability_id,
                    title=candidate.title,
                    payload=candidate.model_dump(mode="json"),
                )
            )
            session.commit()
            return candidate

    def set_status(
        self, finding_id: str, status: FindingStatus, *, analyst_label: FindingStatus | None = None
    ) -> Finding:
        with self._sessions() as session:
            row = session.get(FindingRow, finding_id)
            if row is None:
                raise KeyError(f"finding {finding_id!r} não existe")
            existing = Finding.model_validate(row.payload)
            updated = existing.model_copy(
                update={"status": status, "analyst_label": analyst_label or status}
            )
            row.payload = updated.model_dump(mode="json")
            session.commit()
            return updated

    def list_for_engagement(self, client_id: str, engagement_id: str) -> list[Finding]:
        with self._sessions() as session:
            rows = session.scalars(
                select(FindingRow).where(
                    FindingRow.client_id == client_id, FindingRow.engagement_id == engagement_id
                )
            ).all()
            return [Finding.model_validate(row.payload) for row in rows]


class SqlVulnerabilityRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def get_by_cve(self, cve_id: str) -> Vulnerability | None:
        with self._sessions() as session:
            row = session.scalar(select(VulnerabilityRow).where(VulnerabilityRow.cve_id == cve_id))
            return Vulnerability.model_validate(row.payload) if row else None

    def upsert(self, candidate: Vulnerability) -> Vulnerability:
        if candidate.cve_id is None:
            return candidate

        with self._sessions() as session:
            row = session.scalar(
                select(VulnerabilityRow).where(VulnerabilityRow.cve_id == candidate.cve_id)
            )
            if row is not None:
                existing = Vulnerability.model_validate(row.payload)
                merged = existing.model_copy(
                    update={
                        "cvss_score": candidate.cvss_score
                        if candidate.cvss_score is not None
                        else existing.cvss_score,
                        "cvss_vector": candidate.cvss_vector or existing.cvss_vector,
                        "description": candidate.description or existing.description,
                        "in_cisa_kev": candidate.in_cisa_kev or existing.in_cisa_kev,
                        "references": tuple(
                            sorted(set(existing.references) | set(candidate.references))
                        ),
                        "published_at": candidate.published_at or existing.published_at,
                    }
                )
                row.payload = merged.model_dump(mode="json")
                session.commit()
                return merged

            session.add(
                VulnerabilityRow(
                    id=candidate.id, cve_id=candidate.cve_id, payload=candidate.model_dump(mode="json")
                )
            )
            session.commit()
            return candidate
