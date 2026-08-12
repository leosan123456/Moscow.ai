"""Repositórios SQL de descoberta (`Asset`, `Service`).

`upsert` reproduz exatamente a semântica de fusão de
`vulnai_discovery.repository.InMemoryAssetRepository`/`InMemoryServiceRepository` — só
troca o armazenamento por trás.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from vulnai_shared.models import Asset, Service
from vulnai_persistence.orm import AssetRow, ServiceRow


class SqlAssetRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def upsert(self, candidate: Asset) -> Asset:
        with self._sessions() as session:
            row = session.scalar(
                select(AssetRow).where(
                    AssetRow.client_id == candidate.client_id,
                    AssetRow.identifier == candidate.identifier,
                )
            )
            if row is not None:
                existing = Asset.model_validate(row.payload)
                merged = existing.model_copy(
                    update={
                        "hostnames": tuple(sorted(set(existing.hostnames) | set(candidate.hostnames))),
                        "addresses": tuple(sorted(set(existing.addresses) | set(candidate.addresses))),
                        "tags": tuple(sorted(set(existing.tags) | set(candidate.tags))),
                        "last_seen_at": max(existing.last_seen_at, candidate.last_seen_at),
                    }
                )
                row.payload = merged.model_dump(mode="json")
                session.commit()
                return merged

            session.add(
                AssetRow(
                    id=candidate.id,
                    client_id=candidate.client_id,
                    engagement_id=candidate.engagement_id,
                    identifier=candidate.identifier,
                    payload=candidate.model_dump(mode="json"),
                )
            )
            session.commit()
            return candidate

    def get_by_identifier(self, client_id: str, identifier: str) -> Asset | None:
        with self._sessions() as session:
            row = session.scalar(
                select(AssetRow).where(
                    AssetRow.client_id == client_id, AssetRow.identifier == identifier
                )
            )
            return Asset.model_validate(row.payload) if row else None

    def list_for_engagement(self, client_id: str, engagement_id: str) -> list[Asset]:
        with self._sessions() as session:
            rows = session.scalars(
                select(AssetRow).where(
                    AssetRow.client_id == client_id, AssetRow.engagement_id == engagement_id
                )
            ).all()
            return [Asset.model_validate(row.payload) for row in rows]


class SqlServiceRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def upsert(self, candidate: Service) -> Service:
        with self._sessions() as session:
            row = session.scalar(
                select(ServiceRow).where(
                    ServiceRow.client_id == candidate.client_id,
                    ServiceRow.asset_id == candidate.asset_id,
                    ServiceRow.protocol == candidate.protocol,
                    ServiceRow.port == candidate.port,
                )
            )
            if row is not None:
                existing = Service.model_validate(row.payload)
                merged = existing.model_copy(
                    update={
                        "product": candidate.product or existing.product,
                        "version": candidate.version or existing.version,
                        "cpe": candidate.cpe or existing.cpe,
                        "banner": candidate.banner or existing.banner,
                    }
                )
                row.payload = merged.model_dump(mode="json")
                session.commit()
                return merged

            session.add(
                ServiceRow(
                    id=candidate.id,
                    client_id=candidate.client_id,
                    asset_id=candidate.asset_id,
                    protocol=candidate.protocol,
                    port=candidate.port,
                    payload=candidate.model_dump(mode="json"),
                )
            )
            session.commit()
            return candidate

    def list_for_asset(self, client_id: str, asset_id: str) -> list[Service]:
        with self._sessions() as session:
            rows = session.scalars(
                select(ServiceRow).where(
                    ServiceRow.client_id == client_id, ServiceRow.asset_id == asset_id
                )
            ).all()
            return [Service.model_validate(row.payload) for row in rows]
