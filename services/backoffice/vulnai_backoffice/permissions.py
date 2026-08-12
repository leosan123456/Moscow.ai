"""Catálogo de permissões e papéis do backoffice.

Dois níveis de acesso, deliberadamente separados:

* **Plataforma** — nós (o provedor). Administra clientes, planos, assinaturas e vê a
  trilha de auditoria global. Prefixo `platform:`.
* **Cliente (tenant)** — o cliente contratante. Só enxerga o próprio `client_id`.

Uma permissão de plataforma **nunca** é concedida por um papel de cliente, e um papel de
plataforma só age sobre um tenant quando o vínculo é explícito. O separador de prefixo
não é cosmético: `AccessControl` recusa conceder `platform:*` fora do escopo de plataforma.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class PermissionScope(StrEnum):
    PLATFORM = "platform"
    CLIENT = "client"


class Permission(StrEnum):
    """Permissão granular. O prefixo determina o escopo em que ela pode existir."""

    # ------------------------------------------------------------- plataforma
    PLATFORM_CLIENT_MANAGE = "platform:client.manage"
    PLATFORM_USER_MANAGE = "platform:user.manage"
    PLATFORM_ROLE_MANAGE = "platform:role.manage"
    PLATFORM_PLAN_MANAGE = "platform:plan.manage"
    PLATFORM_SUBSCRIPTION_MANAGE = "platform:subscription.manage"
    PLATFORM_AUDIT_READ = "platform:audit.read"
    PLATFORM_ENGAGEMENT_READ_ALL = "platform:engagement.read_all"
    PLATFORM_POLICY_MANAGE = "platform:policy.manage"
    #: Agir dentro de um tenant a pedido dele. Sempre auditado, nunca silencioso.
    PLATFORM_ACT_ON_TENANT = "platform:tenant.act"

    # ----------------------------------------------------------------- tenant
    CLIENT_USER_MANAGE = "client:user.manage"
    CLIENT_SETTINGS_MANAGE = "client:settings.manage"
    CLIENT_BILLING_READ = "client:billing.read"
    CLIENT_APIKEY_MANAGE = "client:apikey.manage"

    ENGAGEMENT_READ = "engagement:read"
    ENGAGEMENT_MANAGE = "engagement:manage"
    SCOPE_READ = "scope:read"
    SCOPE_MANAGE = "scope:manage"
    SCOPE_TOKEN_ISSUE = "scope_token:issue"
    SCOPE_TOKEN_REVOKE = "scope_token:revoke"

    SCAN_RUN = "scan:run"
    SCAN_RUN_INTRUSIVE = "scan:run_intrusive"
    APPROVAL_GRANT = "approval:grant"

    FINDING_READ = "finding:read"
    FINDING_TRIAGE = "finding:triage"
    AI_INSIGHTS_READ = "ai:insights.read"
    REPORT_READ = "report:read"
    REPORT_EXPORT = "report:export"
    AUDIT_READ = "audit:read"

    @property
    def scope(self) -> PermissionScope:
        if self.value.startswith("platform:"):
            return PermissionScope.PLATFORM
        return PermissionScope.CLIENT

    @property
    def is_platform(self) -> bool:
        return self.scope is PermissionScope.PLATFORM


#: Permissões que representam ação sobre o ambiente do cliente. Concedê-las não basta:
#: o gate de autorização (`services/authorization`) continua valendo em runtime.
TOUCHING_PERMISSIONS: frozenset[Permission] = frozenset(
    {Permission.SCAN_RUN, Permission.SCAN_RUN_INTRUSIVE}
)


@dataclass(frozen=True, slots=True)
class Role:
    """Papel = conjunto nomeado de permissões, válido em um escopo."""

    code: str
    name: str
    scope: PermissionScope
    permissions: frozenset[Permission]
    description: str = ""
    builtin: bool = True

    def __post_init__(self) -> None:
        invalid = [p for p in self.permissions if p.scope is not self.scope]
        if invalid:
            raise ValueError(
                f"papel {self.code!r} de escopo {self.scope.value} não pode conter "
                f"permissões de outro escopo: {sorted(p.value for p in invalid)}"
            )


def _platform(*permissions: Permission) -> frozenset[Permission]:
    return frozenset(permissions)


ALL_PLATFORM_PERMISSIONS: frozenset[Permission] = frozenset(
    p for p in Permission if p.is_platform
)
ALL_CLIENT_PERMISSIONS: frozenset[Permission] = frozenset(
    p for p in Permission if not p.is_platform
)


# --------------------------------------------------------------------------------------
# Papéis de plataforma (acesso global)
# --------------------------------------------------------------------------------------

PLATFORM_ADMIN = Role(
    code="platform_admin",
    name="Administrador global",
    scope=PermissionScope.PLATFORM,
    permissions=ALL_PLATFORM_PERMISSIONS,
    description="Acesso administrativo total à plataforma e a todos os tenants.",
)

PLATFORM_COMMERCIAL = Role(
    code="platform_commercial",
    name="Comercial",
    scope=PermissionScope.PLATFORM,
    permissions=_platform(
        Permission.PLATFORM_CLIENT_MANAGE,
        Permission.PLATFORM_PLAN_MANAGE,
        Permission.PLATFORM_SUBSCRIPTION_MANAGE,
    ),
    description="Gere clientes, planos e assinaturas. Sem acesso a dados de vulnerabilidade.",
)

PLATFORM_ANALYST = Role(
    code="platform_analyst",
    name="Analista da plataforma",
    scope=PermissionScope.PLATFORM,
    permissions=_platform(
        Permission.PLATFORM_ENGAGEMENT_READ_ALL,
        Permission.PLATFORM_ACT_ON_TENANT,
    ),
    description="Opera engajamentos em nome de clientes, com vínculo explícito e auditado.",
)

PLATFORM_AUDITOR = Role(
    code="platform_auditor",
    name="Auditor",
    scope=PermissionScope.PLATFORM,
    permissions=_platform(
        Permission.PLATFORM_AUDIT_READ, Permission.PLATFORM_ENGAGEMENT_READ_ALL
    ),
    description="Somente leitura da trilha de auditoria e do inventário de engajamentos.",
)


# --------------------------------------------------------------------------------------
# Papéis de cliente (tenant)
# --------------------------------------------------------------------------------------

CLIENT_OWNER = Role(
    code="client_owner",
    name="Responsável do cliente",
    scope=PermissionScope.CLIENT,
    permissions=ALL_CLIENT_PERMISSIONS,
    description="Autoridade máxima dentro do tenant, incluindo aprovação de ação intrusiva.",
)

CLIENT_SECURITY_MANAGER = Role(
    code="client_security_manager",
    name="Gestor de segurança",
    scope=PermissionScope.CLIENT,
    permissions=frozenset(
        {
            Permission.ENGAGEMENT_READ,
            Permission.ENGAGEMENT_MANAGE,
            Permission.SCOPE_READ,
            Permission.SCOPE_MANAGE,
            Permission.SCOPE_TOKEN_ISSUE,
            Permission.SCOPE_TOKEN_REVOKE,
            Permission.SCAN_RUN,
            Permission.APPROVAL_GRANT,
            Permission.FINDING_READ,
            Permission.FINDING_TRIAGE,
            Permission.AI_INSIGHTS_READ,
            Permission.REPORT_READ,
            Permission.REPORT_EXPORT,
            Permission.AUDIT_READ,
        }
    ),
    description="Conduz o programa de vulnerabilidades do tenant.",
)

CLIENT_ANALYST = Role(
    code="client_analyst",
    name="Analista do cliente",
    scope=PermissionScope.CLIENT,
    permissions=frozenset(
        {
            Permission.ENGAGEMENT_READ,
            Permission.SCOPE_READ,
            Permission.SCAN_RUN,
            Permission.FINDING_READ,
            Permission.FINDING_TRIAGE,
            Permission.AI_INSIGHTS_READ,
            Permission.REPORT_READ,
        }
    ),
    description="Triagem de achados e execução de varredura não intrusiva.",
)

CLIENT_VIEWER = Role(
    code="client_viewer",
    name="Leitor",
    scope=PermissionScope.CLIENT,
    permissions=frozenset(
        {
            Permission.ENGAGEMENT_READ,
            Permission.SCOPE_READ,
            Permission.FINDING_READ,
            Permission.REPORT_READ,
        }
    ),
    description="Somente leitura. Perfil típico de auditoria interna e stakeholders.",
)

CLIENT_BILLING = Role(
    code="client_billing",
    name="Financeiro",
    scope=PermissionScope.CLIENT,
    permissions=frozenset({Permission.CLIENT_BILLING_READ}),
    description="Vê plano, consumo e faturamento. Sem acesso a dados de vulnerabilidade.",
)


BUILTIN_ROLES: dict[str, Role] = {
    role.code: role
    for role in (
        PLATFORM_ADMIN,
        PLATFORM_COMMERCIAL,
        PLATFORM_ANALYST,
        PLATFORM_AUDITOR,
        CLIENT_OWNER,
        CLIENT_SECURITY_MANAGER,
        CLIENT_ANALYST,
        CLIENT_VIEWER,
        CLIENT_BILLING,
    )
}


def get_role(code: str) -> Role:
    try:
        return BUILTIN_ROLES[code]
    except KeyError as exc:
        raise KeyError(f"papel desconhecido: {code!r}") from exc


def roles_for_scope(scope: PermissionScope) -> list[Role]:
    return [role for role in BUILTIN_ROLES.values() if role.scope is scope]
