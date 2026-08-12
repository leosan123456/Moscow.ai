"""`CollectionService`: fingerprint/scan de imagem passam pelo gate; enriquecimento não."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnai_shared.audit import AuditLog
from vulnai_shared.enums import AuditEventType, Confidence, FindingStatus, Severity
from vulnai_shared.errors import OutOfScopeError
from vulnai_authorization import AuthorizationService, ScopeGuard
from vulnai_collection import (
    CollectionService,
    CveRecord,
    FakeToolRunner,
    StaticKevCatalog,
    StaticNvdCatalog,
    ToolResult,
)
from vulnai_collection.errors import ParseError

FIXTURES = Path(__file__).parent / "fixtures"
NUCLEI_OUTPUT = (FIXTURES / "nuclei_output.jsonl").read_text(encoding="utf-8")
TRIVY_OUTPUT = (FIXTURES / "trivy_output.json").read_text(encoding="utf-8")


@pytest.fixture
def runner() -> FakeToolRunner:
    return FakeToolRunner()


@pytest.fixture
def guard(service: AuthorizationService, token: str, audit: AuditLog) -> ScopeGuard:
    return ScopeGuard(service, token, actor="worker:collection", audit_log=audit)


@pytest.fixture
def nvd() -> StaticNvdCatalog:
    catalog = StaticNvdCatalog()
    catalog.add(CveRecord(cve_id="CVE-2021-41773", title="CVE-2021-41773", cvss_score=9.8))
    catalog.add(CveRecord(cve_id="CVE-2022-37434", title="CVE-2022-37434", cvss_score=None))
    return catalog


@pytest.fixture
def kev() -> StaticKevCatalog:
    return StaticKevCatalog({"CVE-2021-41773"})


@pytest.fixture
def collection(
    guard: ScopeGuard, runner: FakeToolRunner, nvd: StaticNvdCatalog, kev: StaticKevCatalog
) -> CollectionService:
    return CollectionService(
        guard=guard,
        runner=runner,
        client_id="cli-acme",
        engagement_id="eng-001",
        nvd=nvd,
        kev=kev,
    )


# ----------------------------------------------------------------------------- fingerprint


def test_fingerprint_scan_grava_achados_e_enriquece_cve(
    collection: CollectionService, runner: FakeToolRunner
) -> None:
    runner.script(("nuclei",), ToolResult(command=(), returncode=0, stdout=NUCLEI_OUTPUT, stderr=""))

    achados = collection.fingerprint_scan("api.acme.example", asset_id="asset-1")

    assert len(achados) == 3
    com_cve = next(a for a in achados if a.vulnerability_id is not None)
    assert com_cve.severity is Severity.CRITICAL
    assert com_cve.confidence is Confidence.FIRM
    assert com_cve.status is FindingStatus.NEW
    assert com_cve.source_tool == "nuclei"


def test_fingerprint_scan_marca_kev(collection: CollectionService, runner: FakeToolRunner) -> None:
    runner.script(("nuclei",), ToolResult(command=(), returncode=0, stdout=NUCLEI_OUTPUT, stderr=""))
    collection.fingerprint_scan("api.acme.example", asset_id="asset-1")

    vulnerabilidade = collection._vulnerabilities.get_by_cve("CVE-2021-41773")
    assert vulnerabilidade is not None
    assert vulnerabilidade.in_cisa_kev is True


def test_fingerprint_scan_fora_do_escopo_nao_roda_a_ferramenta(
    collection: CollectionService, runner: FakeToolRunner
) -> None:
    with pytest.raises(OutOfScopeError):
        collection.fingerprint_scan("evil.tld", asset_id="asset-1")
    assert runner.calls == []


def test_fingerprint_scan_falha_da_ferramenta(collection: CollectionService, runner: FakeToolRunner) -> None:
    runner.script(("nuclei",), ToolResult(command=(), returncode=1, stdout="", stderr="timeout"))
    with pytest.raises(ParseError, match="timeout"):
        collection.fingerprint_scan("api.acme.example", asset_id="asset-1")


def test_fingerprint_scan_e_auditado(
    collection: CollectionService, runner: FakeToolRunner, audit: AuditLog
) -> None:
    runner.script(("nuclei",), ToolResult(command=(), returncode=0, stdout=NUCLEI_OUTPUT, stderr=""))
    collection.fingerprint_scan("api.acme.example", asset_id="asset-1")

    tocados = [e for e in audit if e.event_type is AuditEventType.ASSET_TOUCHED]
    assert len(tocados) == 1
    assert tocados[0].details["tool"] == "nuclei"


def test_rescan_preserva_falso_positivo_marcado_por_humano(
    collection: CollectionService, runner: FakeToolRunner
) -> None:
    runner.script(("nuclei",), ToolResult(command=(), returncode=0, stdout=NUCLEI_OUTPUT, stderr=""))
    achados = collection.fingerprint_scan("api.acme.example", asset_id="asset-1")

    # Analista revisa e marca falso positivo.
    marcado = achados[0]
    collection._findings.set_status(marcado.id, FindingStatus.FALSE_POSITIVE)

    # Rescan redetecta o mesmo achado — não deve reverter a triagem.
    refeito = collection.fingerprint_scan("api.acme.example", asset_id="asset-1")
    persistido = next(a for a in refeito if a.id == marcado.id)
    assert persistido.status is FindingStatus.FALSE_POSITIVE


# ------------------------------------------------------------------------- imagem de contêiner


def test_scan_container_image_grava_vulnerabilidades(
    collection: CollectionService, runner: FakeToolRunner
) -> None:
    runner.script(("trivy",), ToolResult(command=(), returncode=0, stdout=TRIVY_OUTPUT, stderr=""))

    achados = collection.scan_container_image(
        "registry.acme.example/app:1.4.0", asset_id="asset-container"
    )

    assert len(achados) == 2
    critica = next(a for a in achados if "CVE-2022-37434" in a.evidence)
    assert critica.severity is Severity.CRITICAL


def test_scan_container_image_registro_fora_do_escopo(
    collection: CollectionService, runner: FakeToolRunner
) -> None:
    with pytest.raises(OutOfScopeError):
        collection.scan_container_image("registry.evil.tld/app:latest", asset_id="asset-container")
    assert runner.calls == []


def test_scan_container_image_falha_da_ferramenta(
    collection: CollectionService, runner: FakeToolRunner
) -> None:
    runner.script(("trivy",), ToolResult(command=(), returncode=1, stdout="", stderr="unauthorized"))
    with pytest.raises(ParseError, match="unauthorized"):
        collection.scan_container_image("registry.acme.example/app:1.4.0", asset_id="asset-container")


# ------------------------------------------------------------------------------ enriquecimento


def test_enriquecimento_usa_fallback_de_severidade_pelo_cvss(
    collection: CollectionService, runner: FakeToolRunner, nvd: StaticNvdCatalog
) -> None:
    """CVE-2022-37434 no fixture do trivy já vem com Severity=CRITICAL, então o teste
    força um achado sem severidade textual para provar o fallback via CVSS."""
    nvd.add(CveRecord(cve_id="CVE-9999-0001", title="CVE-9999-0001", cvss_score=8.1))
    import json

    payload = {
        "Results": [
            {
                "Target": "x",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-9999-0001",
                        "PkgName": "libx",
                        "InstalledVersion": "1.0",
                        "Severity": "UNKNOWN",
                    }
                ],
            }
        ]
    }
    runner.script(("trivy",), ToolResult(command=(), returncode=0, stdout=json.dumps(payload), stderr=""))

    achados = collection.scan_container_image("registry.acme.example/app:1.4.0", asset_id="a1")
    assert achados[0].severity is Severity.HIGH  # 8.1 -> HIGH


def test_cve_desconhecido_do_nvd_ainda_vira_achado(
    collection: CollectionService, runner: FakeToolRunner
) -> None:
    """NVD sem registro para o CVE não pode travar o pipeline: o achado é gravado com
    o que se sabe (o próprio id do CVE, veredito do KEV)."""
    import json

    payload = {
        "Results": [
            {
                "Target": "x",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-0000-0000",
                        "PkgName": "libmisteriosa",
                        "InstalledVersion": "1.0",
                        "Severity": "LOW",
                    }
                ],
            }
        ]
    }
    runner.script(("trivy",), ToolResult(command=(), returncode=0, stdout=json.dumps(payload), stderr=""))

    achados = collection.scan_container_image("registry.acme.example/app:1.4.0", asset_id="a1")
    assert len(achados) == 1
    assert achados[0].vulnerability_id is not None
