"""Repositórios de inventário (`Asset`, `Service`).

`upsert` funde pelo identificador natural — `(client_id, identifier)` para ativos,
`(client_id, asset_id, protocol, port)` para serviços — porque descoberta roda
repetidamente sobre o mesmo escopo. Sem fusão, cada rescan duplicaria o inventário em vez
de atualizar `last_seen_at` e os dados de fingerprint.
"""

from __future__ import annotations

from typing import Protocol

from vulnai_shared.models import Asset, Service


class AssetRepository(Protocol):
    def upsert(self, candidate: Asset) -> Asset: ...
    def get_by_identifier(self, client_id: str, identifier: str) -> Asset | None: ...
    def list_for_engagement(self, client_id: str, engagement_id: str) -> list[Asset]: ...


class ServiceRepository(Protocol):
    def upsert(self, candidate: Service) -> Service: ...
    def list_for_asset(self, client_id: str, asset_id: str) -> list[Service]: ...


class InMemoryAssetRepository:
    def __init__(self) -> None:
        self._by_id: dict[str, Asset] = {}
        self._index: dict[tuple[str, str], str] = {}

    def upsert(self, candidate: Asset) -> Asset:
        key = (candidate.client_id, candidate.identifier)
        existing_id = self._index.get(key)
        if existing_id is not None:
            existing = self._by_id[existing_id]
            merged = existing.model_copy(
                update={
                    "hostnames": tuple(sorted(set(existing.hostnames) | set(candidate.hostnames))),
                    "addresses": tuple(sorted(set(existing.addresses) | set(candidate.addresses))),
                    "tags": tuple(sorted(set(existing.tags) | set(candidate.tags))),
                    "criticality": candidate.criticality
                    if candidate.criticality != existing.criticality
                    else existing.criticality,
                    "last_seen_at": max(existing.last_seen_at, candidate.last_seen_at),
                }
            )
            self._by_id[merged.id] = merged
            return merged

        self._by_id[candidate.id] = candidate
        self._index[key] = candidate.id
        return candidate

    def get_by_identifier(self, client_id: str, identifier: str) -> Asset | None:
        asset_id = self._index.get((client_id, identifier))
        return self._by_id.get(asset_id) if asset_id else None

    def list_for_engagement(self, client_id: str, engagement_id: str) -> list[Asset]:
        return [
            a
            for a in self._by_id.values()
            if a.client_id == client_id and a.engagement_id == engagement_id
        ]


class InMemoryServiceRepository:
    def __init__(self) -> None:
        self._by_id: dict[str, Service] = {}
        self._index: dict[tuple[str, str, str, int], str] = {}

    def upsert(self, candidate: Service) -> Service:
        key = (candidate.client_id, candidate.asset_id, candidate.protocol, candidate.port)
        existing_id = self._index.get(key)
        if existing_id is not None:
            existing = self._by_id[existing_id]
            merged = existing.model_copy(
                update={
                    "product": candidate.product or existing.product,
                    "version": candidate.version or existing.version,
                    "cpe": candidate.cpe or existing.cpe,
                    "banner": candidate.banner or existing.banner,
                }
            )
            self._by_id[merged.id] = merged
            return merged

        self._by_id[candidate.id] = candidate
        self._index[key] = candidate.id
        return candidate

    def list_for_asset(self, client_id: str, asset_id: str) -> list[Service]:
        return [
            s for s in self._by_id.values() if s.client_id == client_id and s.asset_id == asset_id
        ]
