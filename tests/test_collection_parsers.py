"""Parsers de coleta: nuclei, trivy e os clientes de enriquecimento (NVD, CISA KEV)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from vulnai_collection.errors import ParseError
from vulnai_collection.kev import HttpKevCatalog, StaticKevCatalog
from vulnai_collection.nuclei import build_command as build_nuclei_command
from vulnai_collection.nuclei import parse_jsonl as parse_nuclei_jsonl
from vulnai_collection.nvd import HttpNvdClient, StaticNvdCatalog, CveRecord
from vulnai_collection.severity import from_cvss, normalize as normalize_severity
from vulnai_collection.trivy import build_command as build_trivy_command
from vulnai_collection.trivy import parse_json as parse_trivy_json
from vulnai_shared.enums import Severity

FIXTURES = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------------------- nuclei


def test_build_nuclei_command_exclui_familias_intrusivas() -> None:
    command = build_nuclei_command("https://api.acme.example")
    assert "-etags" in command
    excluded = command[command.index("-etags") + 1]
    assert {"dos", "fuzz", "intrusive"} <= set(excluded.split(","))


def test_parse_nuclei_extrai_cve_e_severidade() -> None:
    texto = (FIXTURES / "nuclei_output.jsonl").read_text(encoding="utf-8")
    matches = parse_nuclei_jsonl(texto)

    assert len(matches) == 3
    com_cve = matches[0]
    assert com_cve.cve_ids == ("CVE-2021-41773",)
    assert com_cve.severity == "critical"
    assert com_cve.host == "api.acme.example"


def test_parse_nuclei_achado_sem_cve() -> None:
    matches = parse_nuclei_jsonl((FIXTURES / "nuclei_output.jsonl").read_text(encoding="utf-8"))
    sem_cve = [m for m in matches if not m.cve_ids]
    assert len(sem_cve) == 2


def test_parse_nuclei_saida_vazia_nao_e_erro() -> None:
    assert parse_nuclei_jsonl("") == []
    assert parse_nuclei_jsonl("\n\n") == []


def test_parse_nuclei_linha_invalida_levanta_parse_error() -> None:
    with pytest.raises(ParseError):
        parse_nuclei_jsonl("{nao é json}")


# ---------------------------------------------------------------------------------- trivy


def test_build_trivy_command() -> None:
    command = build_trivy_command("registry.acme.example/app:1.4.0")
    assert command == [
        "trivy",
        "image",
        "--format",
        "json",
        "--scanners",
        "vuln",
        "--quiet",
        "registry.acme.example/app:1.4.0",
    ]


def test_parse_trivy_extrai_vulnerabilidades() -> None:
    texto = (FIXTURES / "trivy_output.json").read_text(encoding="utf-8")
    vulns = parse_trivy_json(texto)

    assert {v.cve_id for v in vulns} == {"CVE-2023-44487", "CVE-2022-37434"}
    alta = next(v for v in vulns if v.cve_id == "CVE-2023-44487")
    assert alta.pkg_name == "libnghttp2-14"
    assert alta.fixed_version == "1.52.0-1+deb12u1"
    assert alta.severity == "HIGH"


def test_parse_trivy_ignora_entrada_sem_cve() -> None:
    payload = {
        "Results": [
            {
                "Target": "x",
                "Vulnerabilities": [
                    {"PkgName": "sem-id", "InstalledVersion": "1", "Severity": "LOW"}
                ],
            }
        ]
    }
    assert parse_trivy_json(json.dumps(payload)) == []


def test_parse_trivy_json_invalido() -> None:
    with pytest.raises(ParseError):
        parse_trivy_json("não é json")


# ------------------------------------------------------------------------------ severidade


@pytest.mark.parametrize(
    ("bruta", "esperada"),
    [
        ("critical", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("Medium", Severity.MEDIUM),
        ("low", Severity.LOW),
        ("info", Severity.NONE),
        ("unknown", Severity.NONE),
        (None, Severity.NONE),
        ("algo-nao-mapeado", Severity.NONE),
    ],
)
def test_normalize_severity(bruta: str | None, esperada: Severity) -> None:
    assert normalize_severity(bruta) is esperada


@pytest.mark.parametrize(
    ("score", "esperada"),
    [(9.8, Severity.CRITICAL), (7.5, Severity.HIGH), (5.0, Severity.MEDIUM), (2.0, Severity.LOW), (0.0, Severity.NONE), (None, Severity.NONE)],
)
def test_from_cvss(score: float | None, esperada: Severity) -> None:
    assert from_cvss(score) is esperada


# --------------------------------------------------------------------------------- NVD


def test_static_nvd_catalog() -> None:
    catalog = StaticNvdCatalog()
    catalog.add(CveRecord(cve_id="CVE-2021-41773", title="CVE-2021-41773", cvss_score=9.8))
    assert catalog.get("CVE-2021-41773").cvss_score == 9.8
    assert catalog.get("CVE-9999-0000") is None


def test_http_nvd_client_nunca_toca_a_rede_de_verdade() -> None:
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-41773",
                    "descriptions": [{"lang": "en", "value": "Path traversal in Apache 2.4.49"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "baseScore": 9.8,
                                }
                            }
                        ]
                    },
                    "references": [{"url": "https://httpd.apache.org/security/"}],
                    "published": "2021-10-05T13:15:00.000",
                }
            }
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["cveId"] == "CVE-2021-41773"
        return httpx.Response(200, json=payload)

    client = HttpNvdClient(httpx.Client(transport=httpx.MockTransport(handler)))
    record = client.get("CVE-2021-41773")

    assert record is not None
    assert record.cvss_score == 9.8
    assert record.cvss_vector.startswith("CVSS:3.1")
    assert record.published_at is not None
    assert record.published_at.tzinfo is not None


def test_http_nvd_client_cve_desconhecido() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulnerabilities": []})

    client = HttpNvdClient(httpx.Client(transport=httpx.MockTransport(handler)))
    assert client.get("CVE-0000-0000") is None


# --------------------------------------------------------------------------------- KEV


def test_static_kev_catalog() -> None:
    catalog = StaticKevCatalog({"CVE-2021-41773"})
    assert catalog.contains("CVE-2021-41773")
    assert not catalog.contains("CVE-2022-37434")


def test_http_kev_catalog_faz_cache_apos_o_primeiro_refresh() -> None:
    chamadas = []

    def handler(request: httpx.Request) -> httpx.Response:
        chamadas.append(request)
        return httpx.Response(
            200, json={"vulnerabilities": [{"cveID": "CVE-2021-41773"}, {"cveID": "CVE-2023-44487"}]}
        )

    catalog = HttpKevCatalog(httpx.Client(transport=httpx.MockTransport(handler)))

    assert catalog.contains("CVE-2021-41773")
    assert catalog.contains("CVE-2023-44487")
    assert not catalog.contains("CVE-2022-37434")
    assert len(chamadas) == 1  # segunda e terceira chamada usaram o cache
