"""Correlação com CVE/NVD.

`NvdClient` é o contrato. `HttpNvdClient` fala com a API pública do NVD através de um
`httpx.Client` injetado — em teste, o client usa `httpx.MockTransport`, então a suíte
nunca sai para a rede de verdade. `StaticNvdCatalog` serve um catálogo fixo: útil em
teste e em instalações que mantêm espelho local do NVD (comum nesta categoria de
plataforma, por causa do limite de taxa da API pública).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

import httpx

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass(frozen=True, slots=True)
class CveRecord:
    cve_id: str
    title: str
    description: str | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None
    references: tuple[str, ...] = ()
    published_at: datetime | None = None


class NvdClient(Protocol):
    def get(self, cve_id: str) -> CveRecord | None: ...


class StaticNvdCatalog:
    """Catálogo fixo — teste e instalações com espelho local do NVD."""

    def __init__(self, records: dict[str, CveRecord] | None = None) -> None:
        self._records = dict(records or {})

    def add(self, record: CveRecord) -> None:
        self._records[record.cve_id] = record

    def get(self, cve_id: str) -> CveRecord | None:
        return self._records.get(cve_id)


class HttpNvdClient:
    """Cliente HTTP real. `client` é injetado para que o teste use `MockTransport`."""

    def __init__(self, client: httpx.Client, *, api_key: str | None = None) -> None:
        self._client = client
        self._api_key = api_key

    def get(self, cve_id: str) -> CveRecord | None:
        headers = {"apiKey": self._api_key} if self._api_key else {}
        response = self._client.get(NVD_API_BASE, params={"cveId": cve_id}, headers=headers)
        response.raise_for_status()
        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities") or []
        if not vulnerabilities:
            return None
        return _parse_record(vulnerabilities[0]["cve"])


def _parse_record(cve: dict) -> CveRecord:
    cve_id = cve["id"]
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), None
    )

    cvss_vector = cvss_score = None
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = (cve.get("metrics") or {}).get(metric_key)
        if entries:
            data = entries[0]["cvssData"]
            cvss_vector = data.get("vectorString")
            cvss_score = data.get("baseScore")
            break

    published_at = None
    published_raw = cve.get("published")
    if published_raw:
        parsed = datetime.fromisoformat(published_raw)
        # A API do NVD devolve timestamp sem timezone, implicitamente UTC.
        published_at = parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)

    return CveRecord(
        cve_id=cve_id,
        title=cve_id,
        description=description,
        cvss_vector=cvss_vector,
        cvss_score=cvss_score,
        references=tuple(r["url"] for r in cve.get("references", []) if r.get("url")),
        published_at=published_at,
    )
