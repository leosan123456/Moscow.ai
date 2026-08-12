"""RBAC do backoffice: admin global, acesso por cliente e isolamento entre tenants."""

from __future__ import annotations

from datetime import timedelta

import pytest

from vulnai_shared.clock import FrozenClock
from vulnai_backoffice import (
    BackofficeService,
    Membership,
    MembershipStatus,
    Permission,
    PermissionDeniedError,
    PermissionScope,
    TenantAccessError,
)
from vulnai_backoffice.errors import AuthenticationError
from vulnai_backoffice.repository import InMemoryMembershipRepository

SENHA = "senha-de-teste-123"


# ------------------------------------------------------------------------ autenticação


def test_login_valido_gera_sessao(backoffice: BackofficeService) -> None:
    token = backoffice.login("admin@vulnai.example", SENHA)
    principal = backoffice.principal_from_session(token)
    assert principal.is_platform_admin
    assert principal.scope is PermissionScope.PLATFORM


@pytest.mark.parametrize(
    ("email", "senha"),
    [
        ("admin@vulnai.example", "senha-errada-123"),
        ("naoexiste@vulnai.example", SENHA),
    ],
)
def test_credencial_invalida_da_mesma_mensagem(
    backoffice: BackofficeService, email: str, senha: str
) -> None:
    """Usuário inexistente e senha errada precisam ser indistinguíveis."""
    with pytest.raises(AuthenticationError) as erro:
        backoffice.login(email, senha)
    assert str(erro.value) == "credenciais inválidas"


def test_sessao_expira(backoffice: BackofficeService, clock: FrozenClock) -> None:
    token = backoffice.login("admin@vulnai.example", SENHA)
    clock.advance(timedelta(hours=9).total_seconds())
    with pytest.raises(AuthenticationError):
        backoffice.principal_from_session(token)


def test_logout_invalida_a_sessao(backoffice: BackofficeService) -> None:
    token = backoffice.login("ciso@acme.example", SENHA)
    backoffice.logout(token)
    with pytest.raises(AuthenticationError):
        backoffice.principal_from_session(token, client_id="cli-acme")


def test_login_e_auditado(backoffice: BackofficeService, audit) -> None:  # noqa: ANN001
    backoffice.login("ciso@acme.example", SENHA)
    with pytest.raises(AuthenticationError):
        backoffice.login("ciso@acme.example", "chute-errado-123")

    eventos = [e for e in audit if e.details.get("via") == "password"]
    assert [e.outcome for e in eventos] == ["allow", "deny"]


# ------------------------------------------------------------- separação dos consoles


def test_console_de_plataforma_so_tem_permissoes_de_plataforma(principal_for) -> None:  # noqa: ANN001
    admin = principal_for("admin@vulnai.example")
    assert admin.has(Permission.PLATFORM_CLIENT_MANAGE)
    # Sem tenant selecionado, permissão de tenant não existe.
    assert not admin.has(Permission.SCAN_RUN)


def test_usuario_de_cliente_nao_recebe_permissao_de_plataforma(principal_for) -> None:  # noqa: ANN001
    owner = principal_for("ciso@acme.example", "cli-acme")
    assert owner.has(Permission.ENGAGEMENT_MANAGE)
    assert not owner.has(Permission.PLATFORM_CLIENT_MANAGE)
    with pytest.raises(PermissionDeniedError):
        owner.require(Permission.PLATFORM_SUBSCRIPTION_MANAGE)


def test_usuario_de_cliente_nao_acessa_console_de_plataforma(principal_for) -> None:  # noqa: ANN001
    principal = principal_for("ciso@acme.example")
    assert principal.permissions == frozenset()
    assert not principal.is_platform_admin


# ------------------------------------------------------------------ isolamento tenant


def test_cliente_nao_enxerga_tenant_alheio(backoffice: BackofficeService) -> None:
    token = backoffice.login("ciso@acme.example", SENHA)
    with pytest.raises(TenantAccessError):
        backoffice.principal_from_session(token, client_id="cli-globex")


def test_require_client_bloqueia_operacao_cruzada(principal_for) -> None:  # noqa: ANN001
    owner = principal_for("ciso@acme.example", "cli-acme")
    owner.require_client("cli-acme")
    with pytest.raises(TenantAccessError):
        owner.require_client("cli-globex")


def test_admin_global_opera_no_tenant_por_delegacao(principal_for) -> None:  # noqa: ANN001
    """`platform_admin` tem `platform:tenant.act`, então enxerga e opera o tenant."""
    admin = principal_for("admin@vulnai.example", "cli-acme")
    assert admin.has(Permission.FINDING_READ)
    assert admin.has(Permission.SCAN_RUN)


def test_comercial_entra_no_tenant_so_pelo_lado_comercial(principal_for) -> None:  # noqa: ANN001
    """Cada permissão de plataforma delega um recorte específico dentro do tenant.

    O time comercial precisa ver faturamento e cadastro; não deve ver vulnerabilidade
    nem administrar a base de usuários do cliente.
    """
    comercial = principal_for("comercial@vulnai.example", "cli-acme")
    assert comercial.has(Permission.CLIENT_BILLING_READ)
    assert comercial.has(Permission.CLIENT_SETTINGS_MANAGE)

    assert not comercial.has(Permission.FINDING_READ)
    assert not comercial.has(Permission.SCAN_RUN)
    assert not comercial.has(Permission.CLIENT_USER_MANAGE)
    assert not comercial.has(Permission.AUDIT_READ)


def test_usuario_sem_vinculo_algum_nao_entra_no_tenant(
    backoffice: BackofficeService,
    memberships: InMemoryMembershipRepository,
) -> None:
    memberships.save(
        Membership(
            id="mb-globex-owner",
            user_id="usr-globex-owner",
            scope=PermissionScope.CLIENT,
            client_id="cli-globex",
            role_codes=("client_owner",),
        )
    )
    token = backoffice.login("ciso@globex.example", SENHA)
    with pytest.raises(TenantAccessError):
        backoffice.principal_from_session(token, client_id="cli-acme")


def test_aprovacao_intrusiva_nunca_e_delegada_a_plataforma(principal_for) -> None:  # noqa: ANN001
    """`human_in_the_loop`: quem aprova risco no ambiente do cliente é o cliente."""
    admin = principal_for("admin@vulnai.example", "cli-acme")
    assert not admin.has(Permission.APPROVAL_GRANT)


# -------------------------------------------------------------- negações e exceções


def test_negacao_explicita_vence_o_papel(
    principal_for,  # noqa: ANN001
    memberships: InMemoryMembershipRepository,
) -> None:
    memberships.save(
        Membership(
            id="mb-acme-owner",
            user_id="usr-acme-owner",
            scope=PermissionScope.CLIENT,
            client_id="cli-acme",
            role_codes=("client_owner",),
            denied_permissions=frozenset({Permission.REPORT_EXPORT}),
        )
    )
    owner = principal_for("ciso@acme.example", "cli-acme")
    assert owner.has(Permission.REPORT_READ)
    with pytest.raises(PermissionDeniedError, match="negada explicitamente"):
        owner.require(Permission.REPORT_EXPORT)


def test_concessao_pontual_sem_criar_papel(
    principal_for,  # noqa: ANN001
    memberships: InMemoryMembershipRepository,
) -> None:
    memberships.save(
        Membership(
            id="mb-acme-analista",
            user_id="usr-acme-analista",
            scope=PermissionScope.CLIENT,
            client_id="cli-acme",
            role_codes=("client_analyst",),
            extra_permissions=frozenset({Permission.AUDIT_READ}),
        )
    )
    analista = principal_for("analista@acme.example", "cli-acme")
    assert analista.has(Permission.AUDIT_READ)


def test_vinculo_expirado_nao_da_acesso(
    principal_for,  # noqa: ANN001
    memberships: InMemoryMembershipRepository,
    clock: FrozenClock,
) -> None:
    memberships.save(
        Membership(
            id="mb-acme-analista",
            user_id="usr-acme-analista",
            scope=PermissionScope.CLIENT,
            client_id="cli-acme",
            role_codes=("client_analyst",),
            expires_at=clock() - timedelta(minutes=1),
        )
    )
    with pytest.raises(TenantAccessError):
        principal_for("analista@acme.example", "cli-acme")


def test_vinculo_revogado_nao_da_acesso(
    principal_for,  # noqa: ANN001
    memberships: InMemoryMembershipRepository,
) -> None:
    memberships.save(
        Membership(
            id="mb-acme-analista",
            user_id="usr-acme-analista",
            scope=PermissionScope.CLIENT,
            client_id="cli-acme",
            role_codes=("client_analyst",),
            status=MembershipStatus.REVOKED,
        )
    )
    with pytest.raises(TenantAccessError):
        principal_for("analista@acme.example", "cli-acme")


# ------------------------------------------------------------- escalada de privilégio


def test_ninguem_concede_o_que_nao_tem(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
    memberships: InMemoryMembershipRepository,
) -> None:
    """Analista com gestão de usuários não pode se promover criando um `client_owner`."""
    memberships.save(
        Membership(
            id="mb-acme-analista",
            user_id="usr-acme-analista",
            scope=PermissionScope.CLIENT,
            client_id="cli-acme",
            role_codes=("client_analyst",),
            extra_permissions=frozenset({Permission.CLIENT_USER_MANAGE}),
        )
    )
    analista = principal_for("analista@acme.example", "cli-acme")

    with pytest.raises(PermissionDeniedError, match="não pode conceder"):
        backoffice.grant_membership(
            analista,
            user_id="usr-acme-analista",
            scope=PermissionScope.CLIENT,
            client_id="cli-acme",
            role_codes=("client_owner",),
        )


def test_cliente_nao_concede_vinculo_de_plataforma(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
) -> None:
    owner = principal_for("ciso@acme.example", "cli-acme")
    with pytest.raises(PermissionDeniedError):
        backoffice.grant_membership(
            owner,
            user_id="usr-acme-analista",
            scope=PermissionScope.PLATFORM,
            role_codes=("platform_admin",),
        )


def test_revogar_vinculo_corta_o_acesso(
    backoffice: BackofficeService,
    principal_for,  # noqa: ANN001
) -> None:
    owner = principal_for("ciso@acme.example", "cli-acme")
    backoffice.revoke_membership(owner, membership_id="mb-acme-analista")

    with pytest.raises(TenantAccessError):
        principal_for("analista@acme.example", "cli-acme")


def test_papel_de_escopo_errado_e_rejeitado_na_modelagem() -> None:
    with pytest.raises(ValueError, match="incompatível"):
        Membership(
            user_id="usr-x",
            scope=PermissionScope.CLIENT,
            client_id="cli-acme",
            role_codes=("platform_admin",),
        )


def test_permissao_de_plataforma_nao_entra_por_concessao_pontual() -> None:
    with pytest.raises(ValueError, match="fora do escopo"):
        Membership(
            user_id="usr-x",
            scope=PermissionScope.CLIENT,
            client_id="cli-acme",
            extra_permissions=frozenset({Permission.PLATFORM_AUDIT_READ}),
        )


def test_vinculo_de_plataforma_nao_tem_client_id() -> None:
    with pytest.raises(ValueError, match="não pode ter client_id"):
        Membership(
            user_id="usr-x",
            scope=PermissionScope.PLATFORM,
            client_id="cli-acme",
            role_codes=("platform_auditor",),
        )
