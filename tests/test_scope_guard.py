"""`ScopeGuard`: a fachada que os módulos de varredura são obrigados a usar."""

from __future__ import annotations

import pytest

from vulnai_shared.audit import AuditLog
from vulnai_shared.enums import ActionClass, AuditEventType
from vulnai_shared.errors import OutOfScopeError
from vulnai_authorization import AuthorizationService, ScopeGuard


@pytest.fixture
def guard(service: AuthorizationService, token: str, audit: AuditLog) -> ScopeGuard:
    return ScopeGuard(service, token, actor="analista@vulnai.example", audit_log=audit)


def test_touch_entrega_alvo_normalizado_e_audita(guard: ScopeGuard, audit: AuditLog) -> None:
    with guard.touch("API.Acme.Example", ActionClass.ACTIVE_NON_INTRUSIVE, tool="nmap") as alvo:
        assert alvo.value == "api.acme.example"

    tocados = [e for e in audit if e.event_type is AuditEventType.ASSET_TOUCHED]
    assert len(tocados) == 1
    assert tocados[0].outcome == "completed"
    assert tocados[0].details["tool"] == "nmap"


def test_touch_audita_falha_da_ferramenta(guard: ScopeGuard, audit: AuditLog) -> None:
    with pytest.raises(TimeoutError):  # noqa: PT012 - o corpo do `with` é parte do caso
        with guard.touch("api.acme.example", ActionClass.PASSIVE, tool="nuclei"):
            raise TimeoutError("alvo não respondeu")

    tocados = [e for e in audit if e.event_type is AuditEventType.ASSET_TOUCHED]
    assert tocados[0].outcome == "failed"
    assert "TimeoutError" in tocados[0].details["error"]


def test_touch_nao_entrega_alvo_fora_do_escopo(guard: ScopeGuard) -> None:
    with pytest.raises(OutOfScopeError):  # noqa: PT012
        with guard.touch("evil.tld", ActionClass.PASSIVE, tool="nmap"):
            pytest.fail("o corpo nunca deveria executar para alvo fora do escopo")


def test_partition_separa_candidatos_da_descoberta(guard: ScopeGuard) -> None:
    candidatos = [
        "api.acme.example",
        "www.acme.example",
        "pagamentos.acme.example",  # excluído por contrato
        "cdn.terceiro.example",  # fora do escopo
        "203.0.113.10",
        "203.0.113.9",  # excluído
        "!!alvo inválido!!",
    ]
    autorizados, rejeitados = guard.partition(candidatos, ActionClass.ACTIVE_NON_INTRUSIVE)

    assert autorizados == ["api.acme.example", "www.acme.example", "203.0.113.10"]
    codigos = {r.raw_target: r.error_code for r in rejeitados}
    assert codigos["pagamentos.acme.example"] == "out_of_scope"
    assert codigos["cdn.terceiro.example"] == "out_of_scope"
    assert codigos["!!alvo inválido!!"] == "invalid_target"


def test_partition_deduplica_pela_forma_normalizada(guard: ScopeGuard) -> None:
    """Descoberta entrega o mesmo host em grafias diferentes; varrer duas vezes dobraria
    a carga sobre o ativo do cliente."""
    autorizados, _ = guard.partition(
        ["api.acme.example", "API.Acme.Example", "api.acme.example.", "www.acme.example"],
        ActionClass.PASSIVE,
    )
    assert autorizados == ["api.acme.example", "www.acme.example"]


def test_partition_nao_consome_cota(guard: ScopeGuard) -> None:
    # burst_per_target=3: pré-filtrar 10 vezes não pode gastar a cota real do alvo.
    for _ in range(10):
        guard.partition(["api.acme.example"], ActionClass.PASSIVE)
    for _ in range(3):
        assert guard.authorize("api.acme.example", ActionClass.PASSIVE).allowed
