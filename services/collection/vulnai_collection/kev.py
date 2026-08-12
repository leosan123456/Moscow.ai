"""Catálogo CISA KEV (Known Exploited Vulnerabilities).

`KevCatalog` é o contrato. `StaticKevCatalog` guarda um conjunto fixo de CVE ids — teste
e instalações que sincronizam o feed periodicamente para um espelho local.
`HttpKevCatalog` busca o feed JSON público via `httpx.Client` injetado e cacheia em
memória: o feed é publicado como snapshot completo (não paginado, sem "delta"), então
atualizar significa buscar tudo de novo.
"""

from __future__ import annotations

from typing import Protocol

import httpx

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


class KevCatalog(Protocol):
    def contains(self, cve_id: str) -> bool: ...


class StaticKevCatalog:
    def __init__(self, cve_ids: set[str] | None = None) -> None:
        self._ids = set(cve_ids or ())

    def contains(self, cve_id: str) -> bool:
        return cve_id in self._ids


class HttpKevCatalog:
    def __init__(self, client: httpx.Client) -> None:
        self._client = client
        self._ids: set[str] | None = None

    def refresh(self) -> int:
        response = self._client.get(KEV_FEED_URL)
        response.raise_for_status()
        payload = response.json()
        self._ids = {v["cveID"] for v in payload.get("vulnerabilities", []) if v.get("cveID")}
        return len(self._ids)

    def contains(self, cve_id: str) -> bool:
        if self._ids is None:
            self.refresh()
        assert self._ids is not None
        return cve_id in self._ids
