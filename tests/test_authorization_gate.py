"""O gate ponta a ponta. Se algum destes testes cair, a plataforma não pode varrer nada."""

from __future__ import annotations

from datetime import timedelta

import pytest

from vulnai_shared.clock import FrozenClock
from vulnai_shared.enums import ActionClass, AuditEventType, EngagementStatus
from vulnai_shared.errors import (
    ActionNotAuthorizedError,
    EngagementStateError,
    EngagementWindowError,
    HumanApprovalRequiredError,
    IntrusiveActionNotAuthorizedError,
    OutOfScopeError,
    RateLimitExceededError,
    SafetyPolicyError,
    ScopeDriftError,
    TenantMismatchError,
    TokenExpiredError,
    TokenSignatureError,
)
from vulnai_shared.models import Engagement, Scope, ScopeRule
from vulnai_shared.enums import ScopeRuleKind
from vulnai_shared.audit import AuditLog
from vulnai_authorization import (
    AuthorizationService,
    HumanApproval,
    InMemoryApprovalRepository,
    InMemoryEngagementRepository,
    ScopeTokenSigner,
)


# --------------------------------------------------------------------------- caminho feliz


def test_alvo_no_escopo_e_autorizado(service: AuthorizationService, token: str) -> None:
    decision = service.authorize(token, "api.acme.example", ActionClass.ACTIVE_NON_INTRUSIVE)
    assert decision.allowed
    assert decision.target is not None
    assert decision.target.value == "api.acme.example"
    assert decision.client_id == "cli-acme"


def test_decisao_permitida_gera_evento_de_auditoria(
    service: AuthorizationService, token: str, audit: AuditLog
) -> None:
    service.authorize(token, "203.0.113.10", ActionClass.ACTIVE_NON_INTRUSIVE)
    tipos = [e.event_type for e in audit]
    assert AuditEventType.TOKEN_ISSUED in tipos
    assert AuditEventType.AUTHORIZATION_ALLOWED in tipos
    assert audit.verify() == len(tipos)


# ------------------------------------------------------------------------- fora do escopo


@pytest.mark.parametrize(
    "alvo",
    [
        "evil.tld",
        "evil-acme.example",
        "acme.example.evil.tld",
        "198.51.100.7",
        "203.0.114.10",
        "https://portal.outrocliente.example/",
    ],
)
def test_alvo_fora_do_escopo_e_rejeitado(
    service: AuthorizationService, token: str, alvo: str
) -> None:
    with pytest.raises(OutOfScopeError):
        service.authorize(token, alvo, ActionClass.ACTIVE_NON_INTRUSIVE)


@pytest.mark.parametrize("alvo", ["pagamentos.acme.example", "203.0.113.9"])
def test_alvo_explicitamente_excluido_e_rejeitado(
    service: AuthorizationService, token: str, alvo: str
) -> None:
    with pytest.raises(OutOfScopeError):
        service.authorize(token, alvo, ActionClass.ACTIVE_NON_INTRUSIVE)


def test_negacao_tambem_e_auditada_com_o_alvo_bruto(
    service: AuthorizationService, token: str, audit: AuditLog
) -> None:
    with pytest.raises(OutOfScopeError):
        service.authorize(token, "evil.tld", ActionClass.PASSIVE)

    negados = [e for e in audit if e.event_type is AuditEventType.AUTHORIZATION_DENIED]
    assert len(negados) == 1
    assert negados[0].target == "evil.tld"
    assert negados[0].details["error_code"] == "out_of_scope"
    assert negados[0].engagement_id == "eng-001"


# ------------------------------------------------------------------------------- tokens


def test_token_forjado_e_rejeitado(service: AuthorizationService, token: str) -> None:
    adulterado = token[:-4] + ("aaaa" if not token.endswith("aaaa") else "bbbb")
    with pytest.raises(TokenSignatureError):
        service.authorize(adulterado, "api.acme.example", ActionClass.PASSIVE)


def test_sem_token_nao_ha_autorizacao(service: AuthorizationService) -> None:
    from vulnai_shared.errors import ScopeTokenError

    with pytest.raises(ScopeTokenError):
        service.authorize("", "api.acme.example", ActionClass.PASSIVE)


def test_token_expirado_e_rejeitado(
    service: AuthorizationService, token: str, clock: FrozenClock
) -> None:
    clock.advance(timedelta(hours=9).total_seconds())
    with pytest.raises(TokenExpiredError):
        service.authorize(token, "api.acme.example", ActionClass.PASSIVE)


def test_token_nao_sobrevive_ao_fim_da_janela(
    service: AuthorizationService, clock: FrozenClock
) -> None:
    """TTL de 8h emitido a 2h do fim da janela precisa expirar junto com a janela."""
    clock.advance(timedelta(days=5, hours=22).total_seconds())
    raw = service.issue_scope_token(
        "eng-001", operator="analista@vulnai.example", purpose="coleta tardia"
    )
    clock.advance(timedelta(hours=3).total_seconds())
    with pytest.raises((TokenExpiredError, EngagementWindowError)):
        service.authorize(raw, "api.acme.example", ActionClass.PASSIVE)


def test_token_revogado_para_a_execucao(service: AuthorizationService, token: str) -> None:
    from vulnai_shared.errors import ScopeTokenError

    decision = service.check(token, "api.acme.example", ActionClass.PASSIVE)
    assert decision.token_jti is not None
    service.revoke_scope_token(decision.token_jti, actor="ciso@acme.example", reason="pedido do cliente")

    with pytest.raises(ScopeTokenError):
        service.authorize(token, "api.acme.example", ActionClass.PASSIVE)


def test_mudanca_de_escopo_invalida_tokens_antigos(
    service: AuthorizationService,
    token: str,
    engagement: Engagement,
    engagements: InMemoryEngagementRepository,
) -> None:
    novo_escopo = Scope(
        version=engagement.scope.version + 1,
        rules=(*engagement.scope.rules, ScopeRule(kind=ScopeRuleKind.DOMAIN, value="novo.example")),
    )
    engagements.save(engagement.model_copy(update={"scope": novo_escopo}))

    with pytest.raises(ScopeDriftError):
        service.authorize(token, "api.acme.example", ActionClass.PASSIVE)


def test_token_de_outro_tenant_nao_serve(
    signer: ScopeTokenSigner,
    service: AuthorizationService,
    engagement: Engagement,
    clock: FrozenClock,
) -> None:
    raw = signer.serialize(
        signer.issue(
            client_id="cli-outro",
            engagement_id=engagement.id,
            scope_digest=engagement.scope.digest(),
            scope_version=engagement.scope.version,
            operator="atacante@interno.example",
            max_action=ActionClass.PASSIVE,
            purpose="acesso cruzado",
        )[1]
    )
    with pytest.raises(TenantMismatchError):
        service.authorize(raw, "api.acme.example", ActionClass.PASSIVE)


# ------------------------------------------------------------------- janela e estado


def test_fora_da_janela_nao_emite_token(
    service: AuthorizationService, clock: FrozenClock
) -> None:
    clock.advance(timedelta(days=10).total_seconds())
    with pytest.raises(EngagementWindowError):
        service.issue_scope_token(
            "eng-001", operator="analista@vulnai.example", purpose="fora de hora"
        )


def test_engagement_suspensa_bloqueia_execucao(
    service: AuthorizationService,
    token: str,
    engagement: Engagement,
    engagements: InMemoryEngagementRepository,
) -> None:
    engagements.save(engagement.model_copy(update={"status": EngagementStatus.SUSPENDED}))
    with pytest.raises(EngagementStateError):
        service.authorize(token, "api.acme.example", ActionClass.PASSIVE)


# ------------------------------------------------------------------ classes de ação


def test_acao_acima_do_teto_do_token_e_negada(service: AuthorizationService) -> None:
    passivo = service.issue_scope_token(
        "eng-001",
        operator="analista@vulnai.example",
        purpose="apenas OSINT",
        max_action=ActionClass.PASSIVE,
    )
    with pytest.raises(ActionNotAuthorizedError):
        service.authorize(passivo, "api.acme.example", ActionClass.ACTIVE_NON_INTRUSIVE)


def test_intrusivo_sem_optin_e_negado(service: AuthorizationService) -> None:
    """Engagement sem opt-in não consegue nem emitir token intrusivo."""
    with pytest.raises(ActionNotAuthorizedError):
        service.issue_scope_token(
            "eng-001",
            operator="analista@vulnai.example",
            purpose="tentativa intrusiva",
            max_action=ActionClass.INTRUSIVE,
        )


def test_engagement_intrusiva_exige_aprovacao_humana(
    signer: ScopeTokenSigner,
    audit: AuditLog,
    intrusive_engagement: Engagement,
    approvals: InMemoryApprovalRepository,
    clock: FrozenClock,
) -> None:
    service = AuthorizationService(
        signer=signer,
        audit_log=audit,
        engagements=InMemoryEngagementRepository([intrusive_engagement]),
        approvals=approvals,
        clock=clock,
    )
    raw = service.issue_scope_token(
        "eng-001",
        operator="analista@vulnai.example",
        purpose="validação de RCE em laboratório",
        max_action=ActionClass.INTRUSIVE,
    )

    # Sem aprovação registrada: negado, mesmo com opt-in contratual vigente.
    with pytest.raises(HumanApprovalRequiredError):
        service.authorize(raw, "lab.acme.example", ActionClass.INTRUSIVE)

    approvals.save(
        HumanApproval(
            client_id="cli-acme",
            engagement_id="eng-001",
            target="lab.acme.example",
            action=ActionClass.INTRUSIVE,
            approved_by="ciso@acme.example",
            reference="APROV-2026-77",
            granted_at=clock(),
            expires_at=clock() + timedelta(hours=2),
        )
    )
    assert service.authorize(raw, "lab.acme.example", ActionClass.INTRUSIVE).allowed


def test_intrusivo_fora_do_alvo_do_optin_e_negado(
    signer: ScopeTokenSigner,
    audit: AuditLog,
    intrusive_engagement: Engagement,
    clock: FrozenClock,
) -> None:
    limitada = intrusive_engagement.model_copy(
        update={
            "intrusive_authorization": intrusive_engagement.intrusive_authorization.model_copy(
                update={"limited_to": ("lab.acme.example",)}
            )
        }
    )
    service = AuthorizationService(
        signer=signer,
        audit_log=audit,
        engagements=InMemoryEngagementRepository([limitada]),
        clock=clock,
    )
    raw = service.issue_scope_token(
        "eng-001",
        operator="analista@vulnai.example",
        purpose="validação restrita",
        max_action=ActionClass.INTRUSIVE,
    )
    with pytest.raises(IntrusiveActionNotAuthorizedError):
        service.authorize(raw, "api.acme.example", ActionClass.INTRUSIVE)


# ------------------------------------------------------------------------- política


@pytest.mark.parametrize("alvo", ["127.0.0.1", "localhost", "169.254.169.254", "::1"])
def test_politica_bloqueia_loopback_e_metadados(
    service: AuthorizationService, token: str, alvo: str
) -> None:
    with pytest.raises((SafetyPolicyError, OutOfScopeError)):
        service.authorize(token, alvo, ActionClass.PASSIVE)


def test_politica_e_avaliada_antes_do_escopo(
    signer: ScopeTokenSigner, audit: AuditLog, engagement: Engagement, clock: FrozenClock
) -> None:
    """Mesmo com 169.254.169.254 dentro de um CIDR contratado, a política ganha."""
    escopo_amplo = Scope(
        version=1, rules=(ScopeRule(kind=ScopeRuleKind.CIDR, value="169.254.0.0/16"),)
    )
    aberta = engagement.model_copy(update={"scope": escopo_amplo})
    service = AuthorizationService(
        signer=signer,
        audit_log=audit,
        engagements=InMemoryEngagementRepository([aberta]),
        clock=clock,
    )
    raw = service.issue_scope_token(
        "eng-001", operator="analista@vulnai.example", purpose="teste"
    )
    with pytest.raises(SafetyPolicyError):
        service.authorize(raw, "169.254.169.254", ActionClass.PASSIVE)


# ---------------------------------------------------------------------- intensidade


def test_limite_de_intensidade_por_alvo(service: AuthorizationService, token: str) -> None:
    # burst_per_target=3 na fixture
    for _ in range(3):
        assert service.authorize(token, "api.acme.example", ActionClass.PASSIVE).allowed
    with pytest.raises(RateLimitExceededError):
        service.authorize(token, "api.acme.example", ActionClass.PASSIVE)


def test_limite_recompoe_com_o_tempo(
    service: AuthorizationService, token: str, clock: FrozenClock
) -> None:
    for _ in range(3):
        service.authorize(token, "api.acme.example", ActionClass.PASSIVE)
    clock.advance(1.0)  # 2 req/s -> 2 tokens de volta
    assert service.authorize(token, "api.acme.example", ActionClass.PASSIVE).allowed


def test_limite_e_por_alvo_nao_global(service: AuthorizationService, token: str) -> None:
    for _ in range(3):
        service.authorize(token, "api.acme.example", ActionClass.PASSIVE)
    assert service.authorize(token, "www.acme.example", ActionClass.PASSIVE).allowed


def test_alvo_negado_nao_consome_cota(service: AuthorizationService, token: str) -> None:
    for _ in range(5):
        with pytest.raises(OutOfScopeError):
            service.authorize(token, "evil.tld", ActionClass.PASSIVE)
    for _ in range(3):
        assert service.authorize(token, "api.acme.example", ActionClass.PASSIVE).allowed
