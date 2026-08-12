"""Integração backoffice ↔ gate de escopo.

O caminho completo de um pedido real: pessoa autentica, o RBAC diz se ela pode pedir, o
contrato comercial diz se o produto cobre, e só então o gate de escopo decide o alvo.
As três barreiras são independentes — este arquivo existe para provar que nenhuma delas
supre a ausência da outra.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from vulnai_shared.audit import AuditLog
from vulnai_shared.clock import FrozenClock
from vulnai_shared.enums import ActionClass, AuditEventType, EngagementStatus
from vulnai_shared.errors import OutOfScopeError, TenantMismatchError
from vulnai_shared.models import (
    AuthorizationWindow,
    Engagement,
    Scope,
    ScopeRule,
)
from vulnai_shared.enums import ScopeRuleKind
from vulnai_authorization import (
    AuthorizationService,
    InMemoryEngagementRepository,
    ScopeGuard,
)
from vulnai_backoffice import (
    BackofficeService,
    Membership,
    Permission,
    PermissionScope,
    SubscriptionStatus,
)
from vulnai_backoffice.errors import (
    FeatureNotContractedError,
    PermissionDeniedError,
    SubscriptionInactiveError,
)
from vulnai_backoffice.entitlements import Subscription
from vulnai_backoffice.repository import (
    InMemoryMembershipRepository,
    InMemorySubscriptionRepository,
)


@pytest.fixture
def engagement_globex(clock: FrozenClock) -> Engagement:
    """Engajamento de outro tenant, para testar isolamento na emissão."""
    return Engagement(
        id="eng-globex",
        client_id="cli-globex",
        name="Avaliação Globex",
        contract_reference="CT-2026-0099",
        status=EngagementStatus.ACTIVE,
        scope=Scope(rules=(ScopeRule(kind=ScopeRuleKind.DOMAIN, value="globex.example"),)),
        window=AuthorizationWindow(
            starts_at=clock() - timedelta(days=1), ends_at=clock() + timedelta(days=6)
        ),
    )


# ------------------------------------------------------------------- caminho completo


def test_do_login_ate_a_varredura(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
    service: AuthorizationService,
    audit: AuditLog,
) -> None:
    owner = principal_for("ciso@acme.example", "cli-acme")

    token = backoffice.issue_scope_token(
        owner, engagement_id="eng-001", purpose="varredura trimestral"
    )
    guard = ScopeGuard(service, token, actor=owner.subject, audit_log=audit)

    with guard.touch("api.acme.example", ActionClass.PASSIVE, tool="nuclei") as alvo:
        assert alvo.value == "api.acme.example"

    # E o alvo fora do contrato continua barrado, mesmo com tudo autorizado antes.
    with pytest.raises(OutOfScopeError):
        guard.authorize("evil.tld", ActionClass.PASSIVE)

    assert audit.verify() == len(list(audit))


def test_toda_a_cadeia_fica_na_trilha(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
    service: AuthorizationService,
    audit: AuditLog,
) -> None:
    owner = principal_for("ciso@acme.example", "cli-acme")
    token = backoffice.issue_scope_token(owner, engagement_id="eng-001", purpose="coleta")
    guard = ScopeGuard(service, token, actor=owner.subject, audit_log=audit)
    with guard.touch("api.acme.example", ActionClass.PASSIVE, tool="nmap"):
        pass

    tipos = [e.event_type for e in audit]
    assert AuditEventType.TOKEN_ISSUED in tipos
    assert AuditEventType.AUTHORIZATION_ALLOWED in tipos
    assert all(
        e.client_id == "cli-acme"
        for e in audit
        if e.event_type is AuditEventType.AUTHORIZATION_ALLOWED and e.target
    )


# ----------------------------------------------------------------- barreira do RBAC


def test_leitor_nao_emite_token_de_escopo(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
    memberships: InMemoryMembershipRepository,
) -> None:
    memberships.save(
        Membership(
            id="mb-acme-analista",
            user_id="usr-acme-analista",
            scope=PermissionScope.CLIENT,
            client_id="cli-acme",
            role_codes=("client_viewer",),
        )
    )
    leitor = principal_for("analista@acme.example", "cli-acme")

    with pytest.raises(PermissionDeniedError) as erro:
        backoffice.issue_scope_token(leitor, engagement_id="eng-001", purpose="tentativa")
    assert erro.value.permission == Permission.SCOPE_TOKEN_ISSUE.value


def test_cliente_nao_emite_token_para_engagement_alheia(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
    engagements: InMemoryEngagementRepository,
    engagement_globex: Engagement,
) -> None:
    """Conhecer o id da engagement de outro cliente não pode virar token válido."""
    engagements.save(engagement_globex)
    owner_acme = principal_for("ciso@acme.example", "cli-acme")

    with pytest.raises(TenantMismatchError):
        backoffice.issue_scope_token(
            owner_acme, engagement_id="eng-globex", purpose="acesso cruzado"
        )


# ------------------------------------------------------------ barreira do contrato


def test_plano_sem_intrusivo_barra_antes_do_gate(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
    engagement,  # noqa: ANN001
    intrusive_engagement,  # noqa: ANN001
    engagements: InMemoryEngagementRepository,
) -> None:
    """Mesmo com opt-in contratual de pentest, o plano `professional` não vende intrusivo."""
    engagements.save(intrusive_engagement)
    owner = principal_for("ciso@acme.example", "cli-acme")

    with pytest.raises(FeatureNotContractedError):
        backoffice.issue_scope_token(
            owner,
            engagement_id="eng-001",
            purpose="validação de RCE",
            max_action=ActionClass.INTRUSIVE,
        )


def test_assinatura_suspensa_impede_nova_varredura(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
    subscriptions: InMemorySubscriptionRepository,
    clock: FrozenClock,
) -> None:
    subscriptions.save(
        Subscription(
            client_id="cli-acme",
            plan_code="professional",
            status=SubscriptionStatus.SUSPENDED,
            starts_at=clock() - timedelta(days=30),
        )
    )
    owner = principal_for("ciso@acme.example", "cli-acme")

    with pytest.raises(SubscriptionInactiveError):
        backoffice.issue_scope_token(owner, engagement_id="eng-001", purpose="varredura")


# --------------------------------------------------------------- barreira do escopo


def test_rbac_liberado_nao_dispensa_o_contrato_de_escopo(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
    service: AuthorizationService,
) -> None:
    """Permissão máxima no backoffice não amplia um escopo em nada."""
    admin = principal_for("admin@vulnai.example", "cli-acme")
    token = backoffice.issue_scope_token(
        admin, engagement_id="eng-001", purpose="suporte ao cliente"
    )

    assert service.authorize(token, "api.acme.example", ActionClass.PASSIVE).allowed
    for alvo in ("pagamentos.acme.example", "outro.tld", "203.0.113.9"):
        with pytest.raises(OutOfScopeError):
            service.authorize(token, alvo, ActionClass.PASSIVE)
