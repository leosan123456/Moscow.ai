"""`DiscoveryService`: toda descoberta passa pelo `ScopeGuard` antes de rodar ferramenta."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnai_shared.audit import AuditLog
from vulnai_shared.enums import AssetCriticality, AuditEventType, TargetKind
from vulnai_shared.errors import OutOfScopeError
from vulnai_authorization import AuthorizationService, ScopeGuard
from vulnai_discovery import (
    DiscoveryService,
    FakeToolRunner,
    StaticCloudInventoryProvider,
    ToolResult,
)
from vulnai_discovery.errors import ParseError

FIXTURES = Path(__file__).parent / "fixtures"
NMAP_XML = (FIXTURES / "nmap_scan.xml").read_text(encoding="utf-8")
NMAP_HOST_DOWN_XML = (FIXTURES / "nmap_host_down.xml").read_text(encoding="utf-8")
SUBFINDER_OUTPUT = (FIXTURES / "subfinder_output.txt").read_text(encoding="utf-8")


@pytest.fixture
def runner() -> FakeToolRunner:
    return FakeToolRunner()


@pytest.fixture
def guard(service: AuthorizationService, token: str, audit: AuditLog) -> ScopeGuard:
    return ScopeGuard(service, token, actor="worker:discovery", audit_log=audit)


@pytest.fixture
def discovery(guard: ScopeGuard, runner: FakeToolRunner) -> DiscoveryService:
    return DiscoveryService(
        guard=guard, runner=runner, client_id="cli-acme", engagement_id="eng-001"
    )


# -------------------------------------------------------------------------------- hosts


def test_scan_host_grava_ativo_e_servicos(discovery: DiscoveryService, runner: FakeToolRunner) -> None:
    runner.script(("nmap",), ToolResult(command=(), returncode=0, stdout=NMAP_XML, stderr=""))

    asset = discovery.scan_host("api.acme.example")

    assert asset.identifier == "api.acme.example"
    assert asset.kind is TargetKind.HOSTNAME
    assert asset.addresses == ("203.0.113.10",)
    assert asset.client_id == "cli-acme"
    assert asset.engagement_id == "eng-001"

    servicos = discovery.services_of(asset.id)
    assert len(servicos) == 1
    assert servicos[0].port == 443
    assert servicos[0].product == "nginx"
    assert servicos[0].cpe == "cpe:/a:nginx:nginx:1.24.0"


def test_scan_host_usa_criticidade_informada(discovery: DiscoveryService, runner: FakeToolRunner) -> None:
    runner.script(("nmap",), ToolResult(command=(), returncode=0, stdout=NMAP_XML, stderr=""))
    asset = discovery.scan_host("api.acme.example", criticality=AssetCriticality.HIGH)
    assert asset.criticality is AssetCriticality.HIGH


def test_scan_host_fora_do_escopo_nao_chega_a_chamar_a_ferramenta(
    discovery: DiscoveryService, runner: FakeToolRunner
) -> None:
    with pytest.raises(OutOfScopeError):
        discovery.scan_host("evil.tld")
    assert runner.calls == []


def test_scan_host_sem_host_ativo_levanta_parse_error(
    discovery: DiscoveryService, runner: FakeToolRunner
) -> None:
    runner.script(
        ("nmap",), ToolResult(command=(), returncode=0, stdout=NMAP_HOST_DOWN_XML, stderr="")
    )
    with pytest.raises(ParseError, match="não reportou nenhum host"):
        discovery.scan_host("api.acme.example")


def test_scan_host_com_falha_da_ferramenta_levanta_parse_error(
    discovery: DiscoveryService, runner: FakeToolRunner
) -> None:
    runner.script(
        ("nmap",), ToolResult(command=(), returncode=1, stdout="", stderr="permission denied")
    )
    with pytest.raises(ParseError, match="permission denied"):
        discovery.scan_host("api.acme.example")


def test_rescan_atualiza_em_vez_de_duplicar(
    discovery: DiscoveryService, runner: FakeToolRunner
) -> None:
    runner.script(("nmap",), ToolResult(command=(), returncode=0, stdout=NMAP_XML, stderr=""))

    primeiro = discovery.scan_host("api.acme.example")
    segundo = discovery.scan_host("api.acme.example")

    assert primeiro.id == segundo.id
    assert len(discovery.inventory()) == 1
    assert segundo.last_seen_at >= primeiro.first_seen_at


def test_scan_host_e_auditado(discovery: DiscoveryService, runner: FakeToolRunner, audit: AuditLog) -> None:
    runner.script(("nmap",), ToolResult(command=(), returncode=0, stdout=NMAP_XML, stderr=""))
    discovery.scan_host("api.acme.example")

    tocados = [e for e in audit if e.event_type is AuditEventType.ASSET_TOUCHED]
    assert len(tocados) == 1
    assert tocados[0].details["tool"] == "nmap"
    assert tocados[0].outcome == "completed"


# --------------------------------------------------------------------- subdomínios


def test_enumerate_subdomains_particiona_por_escopo(
    discovery: DiscoveryService, runner: FakeToolRunner
) -> None:
    runner.script(
        ("subfinder",), ToolResult(command=(), returncode=0, stdout=SUBFINDER_OUTPUT, stderr="")
    )

    resultado = discovery.enumerate_subdomains("acme.example")

    assert "www.acme.example" in resultado.in_scope
    assert "staging.acme.example" in resultado.in_scope
    # excluído pelo contrato e fora do domínio, respectivamente
    codigos = {r.raw_target for r in resultado.rejected}
    assert "pagamentos.acme.example" in codigos
    assert "cdn.terceiro.example" in codigos


def test_enumerate_subdomains_dominio_fora_do_escopo_nao_roda_a_ferramenta(
    discovery: DiscoveryService, runner: FakeToolRunner
) -> None:
    with pytest.raises(OutOfScopeError):
        discovery.enumerate_subdomains("outro-dominio.tld")
    assert runner.calls == []


# --------------------------------------------------------------------------- nuvem


def test_ingest_cloud_inventory_registra_recursos(
    service: AuthorizationService, runner: FakeToolRunner, audit: AuditLog, engagements
) -> None:  # noqa: ANN001
    from vulnai_shared.enums import ActionClass, ScopeRuleKind
    from vulnai_shared.models import Scope, ScopeRule

    engagement = engagements.get("eng-001")
    engagements.save(
        engagement.model_copy(
            update={
                "scope": Scope(
                    version=engagement.scope.version + 1,
                    rules=(
                        *engagement.scope.rules,
                        ScopeRule(kind=ScopeRuleKind.CLOUD_ACCOUNT, value="aws:123456789012"),
                    ),
                )
            }
        )
    )
    novo_token = service.issue_scope_token(
        "eng-001",
        operator="analista@vulnai.example",
        purpose="inventário cloud",
        max_action=ActionClass.ACTIVE_NON_INTRUSIVE,
    )
    guard = ScopeGuard(service, novo_token, actor="worker:discovery", audit_log=audit)
    discovery = DiscoveryService(
        guard=guard, runner=runner, client_id="cli-acme", engagement_id="eng-001"
    )
    provider = StaticCloudInventoryProvider(
        resources_by_account={"123456789012": ("s3/bucket-logs", "ec2/i-0123abcd")}
    )

    ativos = discovery.ingest_cloud_inventory(provider, "aws:123456789012")

    identificadores = {a.identifier for a in ativos}
    assert identificadores == {
        "aws:123456789012/s3/bucket-logs",
        "aws:123456789012/ec2/i-0123abcd",
    }
    assert all(a.kind is TargetKind.CLOUD_RESOURCE for a in ativos)


def test_ingest_cloud_inventory_conta_fora_do_escopo(
    discovery: DiscoveryService,
) -> None:
    provider = StaticCloudInventoryProvider(resources_by_account={"999999999999": ("s3/x",)})
    with pytest.raises(OutOfScopeError):
        discovery.ingest_cloud_inventory(provider, "aws:999999999999")
