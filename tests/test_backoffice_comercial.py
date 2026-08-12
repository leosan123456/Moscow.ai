"""Camada comercial: o plano recorta o que o papel consegue de fato exercer."""

from __future__ import annotations

from datetime import timedelta

import pytest

from vulnai_shared.clock import FrozenClock
from vulnai_backoffice import (
    BackofficeService,
    Feature,
    Membership,
    Permission,
    PermissionScope,
    Quota,
    QuotaExceededError,
    SubscriptionStatus,
)
from vulnai_backoffice.entitlements import (
    ENTERPRISE,
    ESSENTIAL,
    PROFESSIONAL,
    UNLIMITED,
    Subscription,
    resolve_entitlements,
)
from vulnai_backoffice.errors import (
    FeatureNotContractedError,
    NotFoundError,
    PermissionDeniedError,
    SubscriptionInactiveError,
)
from vulnai_backoffice.repository import (
    InMemoryMembershipRepository,
    InMemorySubscriptionRepository,
)


# --------------------------------------------------------------- resolução de plano


def test_plano_essencial_nao_inclui_llm_nem_intrusivo(clock: FrozenClock) -> None:
    ent = resolve_entitlements(
        Subscription(
            client_id="cli-x",
            plan_code="essential",
            status=SubscriptionStatus.ACTIVE,
            starts_at=clock(),
        ),
        clock(),
    )
    assert ent.has(Feature.ASSET_DISCOVERY)
    assert not ent.has(Feature.LLM_RAG_ANALYST)
    assert not ent.has(Feature.INTRUSIVE_CHECKS)
    assert ent.quota(Quota.MAX_ENGAGEMENTS) == 1


def test_addon_e_exclusao_ajustam_o_plano_base(clock: FrozenClock) -> None:
    """Add-on vendido por fora e funcionalidade que o próprio cliente pediu para desligar."""
    ent = resolve_entitlements(
        Subscription(
            client_id="cli-x",
            plan_code="essential",
            status=SubscriptionStatus.ACTIVE,
            starts_at=clock(),
            extra_features=frozenset({Feature.LLM_RAG_ANALYST}),
            excluded_features=frozenset({Feature.ASSET_DISCOVERY}),
            quota_overrides={Quota.MAX_ASSETS: 1000},
        ),
        clock(),
    )
    assert ent.has(Feature.LLM_RAG_ANALYST)
    assert not ent.has(Feature.ASSET_DISCOVERY)
    assert ent.quota(Quota.MAX_ASSETS) == 1000


def test_assinatura_cancelada_nao_da_entitlement(clock: FrozenClock) -> None:
    ent = resolve_entitlements(
        Subscription(
            client_id="cli-x",
            plan_code="enterprise",
            status=SubscriptionStatus.CANCELLED,
            starts_at=clock() - timedelta(days=1),
        ),
        clock(),
    )
    assert not ent.active
    assert ent.features == frozenset()


def test_assinatura_futura_ainda_nao_vale(clock: FrozenClock) -> None:
    ent = resolve_entitlements(
        Subscription(
            client_id="cli-x",
            plan_code="enterprise",
            status=SubscriptionStatus.ACTIVE,
            starts_at=clock() + timedelta(days=2),
        ),
        clock(),
    )
    assert not ent.active


def test_inadimplencia_nao_cega_o_cliente(clock: FrozenClock) -> None:
    """`past_due` mantém acesso: risco já existente não some porque a fatura atrasou."""
    ent = resolve_entitlements(
        Subscription(
            client_id="cli-x",
            plan_code="professional",
            status=SubscriptionStatus.PAST_DUE,
            starts_at=clock() - timedelta(days=1),
        ),
        clock(),
    )
    assert ent.active


def test_plano_fora_do_catalogo_nao_vira_acesso_total(clock: FrozenClock) -> None:
    ent = resolve_entitlements(
        Subscription(
            client_id="cli-x",
            plan_code="plano-descontinuado",
            status=SubscriptionStatus.ACTIVE,
            starts_at=clock(),
        ),
        clock(),
    )
    assert not ent.active
    assert ent.features == frozenset()


def test_catalogo_e_progressivo() -> None:
    assert ENTERPRISE.quota(Quota.MAX_ASSETS) == UNLIMITED
    assert ESSENTIAL.quota(Quota.MAX_ASSETS) < PROFESSIONAL.quota(Quota.MAX_ASSETS)
    assert ESSENTIAL.features < PROFESSIONAL.features < ENTERPRISE.features


# -------------------------------------------------- plano recorta a permissão do papel


def test_owner_perde_intrusivo_se_o_plano_nao_inclui(principal_for) -> None:  # noqa: ANN001
    """ACME está no `professional`, que não inclui `INTRUSIVE_CHECKS`."""
    owner = principal_for("ciso@acme.example", "cli-acme")
    assert owner.has(Permission.SCAN_RUN)
    assert not owner.has(Permission.SCAN_RUN_INTRUSIVE)

    with pytest.raises(FeatureNotContractedError) as erro:
        owner.require(Permission.SCAN_RUN_INTRUSIVE)
    assert erro.value.feature == Feature.INTRUSIVE_CHECKS.value


def test_upgrade_de_plano_libera_a_permissao(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
    clock: FrozenClock,
) -> None:
    admin = principal_for("admin@vulnai.example")
    backoffice.set_subscription(
        admin,
        client_id="cli-acme",
        plan_code="enterprise",
        status=SubscriptionStatus.ACTIVE,
        starts_at=clock() - timedelta(days=1),
    )
    owner = principal_for("ciso@acme.example", "cli-acme")
    assert owner.has(Permission.SCAN_RUN_INTRUSIVE)


def test_admin_global_tambem_respeita_o_plano_do_cliente(principal_for) -> None:  # noqa: ANN001
    """O contrato do cliente limita a plataforma inteira, inclusive nós."""
    admin = principal_for("admin@vulnai.example", "cli-acme")
    assert not admin.has(Permission.SCAN_RUN_INTRUSIVE)


def test_plano_essencial_nao_exporta_relatorio_customizado(principal_for) -> None:  # noqa: ANN001
    globex = principal_for("ciso@globex.example", "cli-globex")
    assert globex.has(Permission.REPORT_READ)
    with pytest.raises(FeatureNotContractedError):
        globex.require(Permission.REPORT_EXPORT)


def test_sem_assinatura_o_tenant_fica_em_leitura(
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

    assert owner.has(Permission.FINDING_READ)  # histórico continua visível
    assert not owner.has(Permission.SCAN_RUN)
    with pytest.raises(SubscriptionInactiveError):
        owner.require(Permission.SCOPE_TOKEN_ISSUE)


# ---------------------------------------------------------------------------- cotas


def test_cota_de_usuarios_bloqueia_novo_convite(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
    clock: FrozenClock,
) -> None:
    admin = principal_for("admin@vulnai.example")
    backoffice.set_subscription(
        admin,
        client_id="cli-acme",
        plan_code="professional",
        status=SubscriptionStatus.ACTIVE,
        starts_at=clock() - timedelta(days=1),
        quota_overrides={Quota.MAX_USERS: 2},
    )
    owner = principal_for("ciso@acme.example", "cli-acme")

    # A ACME já tem 2 usuários vinculados (owner + analista).
    with pytest.raises(QuotaExceededError) as erro:
        backoffice.invite_client_user(
            owner,
            client_id="cli-acme",
            email="novo@acme.example",
            full_name="Novo Usuário",
            role_codes=("client_viewer",),
        )
    assert erro.value.quota == Quota.MAX_USERS.value
    assert erro.value.limit == 2


def test_cota_ilimitada_nao_bloqueia(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
    clock: FrozenClock,
) -> None:
    admin = principal_for("admin@vulnai.example")
    backoffice.set_subscription(
        admin,
        client_id="cli-acme",
        plan_code="enterprise",
        status=SubscriptionStatus.ACTIVE,
        starts_at=clock() - timedelta(days=1),
    )
    owner = principal_for("ciso@acme.example", "cli-acme")
    usuario, vinculo = backoffice.invite_client_user(
        owner,
        client_id="cli-acme",
        email="novo@acme.example",
        full_name="Novo Usuário",
        role_codes=("client_viewer",),
    )
    assert usuario.email == "novo@acme.example"
    assert vinculo.client_id == "cli-acme"


# --------------------------------------------------------------- gestão comercial


def test_comercial_gere_plano_mas_nao_ve_vulnerabilidade(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
    clock: FrozenClock,
) -> None:
    comercial = principal_for("comercial@vulnai.example")
    assinatura = backoffice.set_subscription(
        comercial,
        client_id="cli-globex",
        plan_code="professional",
        status=SubscriptionStatus.ACTIVE,
        starts_at=clock(),
    )
    assert assinatura.plan_code == "professional"
    assert not comercial.has(Permission.PLATFORM_ENGAGEMENT_READ_ALL)


def test_auditor_nao_altera_assinatura(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
    memberships: InMemoryMembershipRepository,
) -> None:
    memberships.save(
        Membership(
            id="mb-comercial",
            user_id="usr-comercial",
            scope=PermissionScope.PLATFORM,
            role_codes=("platform_auditor",),
        )
    )
    auditor = principal_for("comercial@vulnai.example")
    with pytest.raises(PermissionDeniedError):
        backoffice.set_subscription(auditor, client_id="cli-acme", plan_code="essential")


def test_assinatura_para_cliente_inexistente_e_recusada(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
) -> None:
    admin = principal_for("admin@vulnai.example")
    with pytest.raises(NotFoundError):
        backoffice.set_subscription(admin, client_id="cli-fantasma", plan_code="essential")


def test_plano_inexistente_e_recusado(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
) -> None:
    admin = principal_for("admin@vulnai.example")
    with pytest.raises(NotFoundError):
        backoffice.set_subscription(admin, client_id="cli-acme", plan_code="plano-vip-secreto")


def test_mudanca_de_plano_e_auditada(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
    audit,  # noqa: ANN001
) -> None:
    admin = principal_for("admin@vulnai.example")
    backoffice.set_subscription(admin, client_id="cli-acme", plan_code="enterprise")

    eventos = [e for e in audit if e.details.get("event") == "subscription.changed"]
    assert eventos[-1].details["from_plan"] == "professional"
    assert eventos[-1].details["to_plan"] == "enterprise"
    assert eventos[-1].client_id == "cli-acme"
    assert audit.verify() == len(list(audit))


# ------------------------------------------------------- chave de API (gated por plano)


def test_chave_de_api_exige_funcionalidade_contratada(principal_for) -> None:  # noqa: ANN001
    """Globex está no `essential`, sem `API_ACCESS`."""
    globex = principal_for("ciso@globex.example", "cli-globex")
    assert not globex.has(Permission.CLIENT_APIKEY_MANAGE)


def test_chave_de_api_autentica_e_herda_o_vinculo(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
) -> None:
    owner = principal_for("ciso@acme.example", "cli-acme")
    raw, api_key = backoffice.create_api_key(owner, name="pipeline-ci")

    principal = backoffice.principal_from_api_key(raw)
    assert principal.via == "api_key"
    assert principal.client_id == "cli-acme"
    assert principal.has(Permission.FINDING_READ)
    assert api_key.client_id == "cli-acme"


def test_chave_revogada_nao_autentica(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
) -> None:
    from vulnai_backoffice.errors import AuthenticationError

    owner = principal_for("ciso@acme.example", "cli-acme")
    raw, api_key = backoffice.create_api_key(owner, name="pipeline-ci")
    backoffice.revoke_api_key(owner, key_id=api_key.key_id)

    with pytest.raises(AuthenticationError):
        backoffice.principal_from_api_key(raw)


def test_revogar_vinculo_revoga_as_chaves_dele(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
    memberships: InMemoryMembershipRepository,
) -> None:
    from vulnai_backoffice import MembershipStatus
    from vulnai_backoffice.errors import AuthenticationError

    owner = principal_for("ciso@acme.example", "cli-acme")
    raw, _ = backoffice.create_api_key(owner, name="pipeline-ci")

    vinculo = memberships.get("mb-acme-owner")
    assert vinculo is not None
    memberships.save(vinculo.model_copy(update={"status": MembershipStatus.REVOKED}))

    with pytest.raises(AuthenticationError):
        backoffice.principal_from_api_key(raw)
