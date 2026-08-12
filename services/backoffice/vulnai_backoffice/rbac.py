"""Resolução de permissão efetiva.

A permissão que vale no runtime é o resultado de quatro camadas, nesta ordem:

    1. papéis do vínculo (`Membership.role_codes`)
    2. concessões pontuais (`extra_permissions`)
    3. delegação de plataforma, quando um usuário nosso age dentro de um tenant
    4. **subtrações**: negações explícitas e bloqueios comerciais do plano

Subtração é sempre a última etapa e nunca é reversível por camada anterior. Um
`client_owner` com `scan:run_intrusive` no papel não recebe a permissão se o plano não
inclui `INTRUSIVE_CHECKS` — e o admin global também não, agindo dentro daquele tenant.
Isso é deliberado: o contrato do cliente define o que a plataforma pode oferecer a ele,
inclusive para nós.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime

from vulnai_backoffice.entitlements import (
    NO_ENTITLEMENTS,
    Entitlements,
    Feature,
    Quota,
)
from vulnai_backoffice.errors import (
    FeatureNotContractedError,
    PermissionDeniedError,
    QuotaExceededError,
    SubscriptionInactiveError,
    TenantAccessError,
)
from vulnai_backoffice.models import Membership
from vulnai_backoffice.permissions import Permission, PermissionScope, get_role

#: O que cada permissão de plataforma habilita **dentro** de um tenant. Sem esta tabela,
#: um admin global não teria nenhuma permissão de tenant — o que é o padrão correto:
#: acesso a dado de cliente é delegação explícita, não consequência do cargo.
PLATFORM_TENANT_DELEGATION: dict[Permission, frozenset[Permission]] = {
    Permission.PLATFORM_ACT_ON_TENANT: frozenset(
        {
            Permission.ENGAGEMENT_READ,
            Permission.ENGAGEMENT_MANAGE,
            Permission.SCOPE_READ,
            Permission.SCOPE_TOKEN_ISSUE,
            Permission.SCOPE_TOKEN_REVOKE,
            Permission.SCAN_RUN,
            Permission.FINDING_READ,
            Permission.FINDING_TRIAGE,
            Permission.AI_INSIGHTS_READ,
            Permission.REPORT_READ,
        }
    ),
    Permission.PLATFORM_ENGAGEMENT_READ_ALL: frozenset(
        {
            Permission.ENGAGEMENT_READ,
            Permission.SCOPE_READ,
            Permission.FINDING_READ,
            Permission.REPORT_READ,
        }
    ),
    Permission.PLATFORM_AUDIT_READ: frozenset({Permission.AUDIT_READ}),
    Permission.PLATFORM_CLIENT_MANAGE: frozenset({Permission.CLIENT_SETTINGS_MANAGE}),
    #: Gestão da base de usuários de um tenant deriva de gestão de usuários da
    #: plataforma, não de cadastro comercial: criar conta dentro do tenant é caminho
    #: direto para os dados dele, e o time comercial não deve tê-lo.
    Permission.PLATFORM_USER_MANAGE: frozenset({Permission.CLIENT_USER_MANAGE}),
    Permission.PLATFORM_SUBSCRIPTION_MANAGE: frozenset({Permission.CLIENT_BILLING_READ}),
}

#: Permissões que exigem assinatura vigente. Sem contrato ativo, o tenant fica em
#: leitura: ninguém varre nem emite token, mas o histórico continua acessível.
SUBSCRIPTION_REQUIRED_PERMISSIONS: frozenset[Permission] = frozenset(
    {
        Permission.SCAN_RUN,
        Permission.SCAN_RUN_INTRUSIVE,
        Permission.SCOPE_TOKEN_ISSUE,
        Permission.ENGAGEMENT_MANAGE,
        Permission.SCOPE_MANAGE,
        Permission.APPROVAL_GRANT,
    }
)

#: Aprovação humana de ação intrusiva nunca vem por delegação de plataforma: quem aprova
#: risco no ambiente do cliente é o cliente (princípio `human_in_the_loop`).
NEVER_DELEGATED: frozenset[Permission] = frozenset({Permission.APPROVAL_GRANT})


@dataclass(frozen=True, slots=True)
class Principal:
    """Identidade resolvida para um contexto de acesso (uma requisição)."""

    subject: str
    user_id: str
    scope: PermissionScope
    #: Tenant ativo. `None` = console de plataforma.
    client_id: str | None
    permissions: frozenset[Permission]
    entitlements: Entitlements = NO_ENTITLEMENTS
    is_platform_admin: bool = False
    #: Como autenticou: `session`, `api_key` ou `service`.
    via: str = "session"
    membership_ids: tuple[str, ...] = ()
    denied: frozenset[Permission] = frozenset()
    details: dict[str, str] = field(default_factory=dict)

    # ---------------------------------------------------------------- consulta
    def has(self, permission: Permission) -> bool:
        return permission in self.permissions

    def has_all(self, *permissions: Permission) -> bool:
        return all(p in self.permissions for p in permissions)

    def require(self, permission: Permission) -> None:
        """Levanta se faltar a permissão, explicando **por que** faltou."""
        if permission in self.permissions:
            return

        if permission in self.denied:
            raise PermissionDeniedError(
                f"{self.subject}: permissão {permission.value} negada explicitamente "
                "no vínculo",
                permission=permission.value,
            )

        blocked = self.entitlements.blocked_permissions()
        if permission in blocked:
            feature = _feature_for(permission)
            raise FeatureNotContractedError(
                f"{permission.value} exige a funcionalidade "
                f"{feature.value if feature else '?'}, não incluída no plano "
                f"{self.entitlements.plan_code or '(sem assinatura)'}",
                feature=feature.value if feature else None,
            )
        if permission in SUBSCRIPTION_REQUIRED_PERMISSIONS and not self.entitlements.active:
            raise SubscriptionInactiveError(
                f"{permission.value} exige assinatura vigente para o cliente "
                f"{self.client_id}"
            )
        raise PermissionDeniedError(
            f"{self.subject} não possui a permissão {permission.value}",
            permission=permission.value,
        )

    def require_client(self, client_id: str) -> None:
        """Confere que o principal está de fato operando neste tenant."""
        if self.client_id != client_id:
            raise TenantAccessError(
                f"{self.subject} não está vinculado ao cliente {client_id}",
            )

    def require_feature(self, feature: Feature) -> None:
        if not self.entitlements.has(feature):
            raise FeatureNotContractedError(
                f"funcionalidade {feature.value} não contratada no plano "
                f"{self.entitlements.plan_code or '(sem assinatura)'}",
                feature=feature.value,
            )

    def require_quota(self, quota: Quota, current_usage: int) -> None:
        if not self.entitlements.within_quota(quota, current_usage):
            limit = self.entitlements.quota(quota)
            raise QuotaExceededError(
                f"limite de {quota.value} atingido ({current_usage}/{limit}) "
                f"no plano {self.entitlements.plan_code}",
                quota=quota.value,
                limit=limit,
            )


def resolve_principal(
    *,
    subject: str,
    user_id: str,
    memberships: Sequence[Membership],
    moment: datetime,
    client_id: str | None = None,
    entitlements: Entitlements = NO_ENTITLEMENTS,
    via: str = "session",
) -> Principal:
    """Calcula as permissões efetivas de um usuário num tenant (ou na plataforma).

    `client_id=None` resolve o console de plataforma: apenas permissões `platform:*`.
    """
    active = [m for m in memberships if m.user_id == user_id and m.is_active(moment)]

    platform_links = [m for m in active if m.scope is PermissionScope.PLATFORM]
    tenant_links = [
        m
        for m in active
        if m.scope is PermissionScope.CLIENT and client_id is not None and m.client_id == client_id
    ]

    platform_permissions = _permissions_of(platform_links)
    is_admin = Permission.PLATFORM_CLIENT_MANAGE in platform_permissions and (
        Permission.PLATFORM_USER_MANAGE in platform_permissions
    )

    if client_id is None:
        denied = _denied_of(platform_links)
        return Principal(
            subject=subject,
            user_id=user_id,
            scope=PermissionScope.PLATFORM,
            client_id=None,
            permissions=frozenset(platform_permissions - denied),
            entitlements=NO_ENTITLEMENTS,
            is_platform_admin=is_admin,
            via=via,
            membership_ids=tuple(m.id for m in platform_links),
            denied=frozenset(denied),
        )

    if not tenant_links and not platform_permissions:
        raise TenantAccessError(f"{subject} não está vinculado ao cliente {client_id}")

    granted = _permissions_of(tenant_links) | _delegated(platform_permissions)
    denied = _denied_of(tenant_links) | _denied_of(platform_links)

    effective = granted - denied
    effective -= entitlements.blocked_permissions()
    if not entitlements.active:
        effective -= SUBSCRIPTION_REQUIRED_PERMISSIONS

    if not effective:
        raise TenantAccessError(
            f"{subject} não possui nenhuma permissão efetiva no cliente {client_id}"
        )

    return Principal(
        subject=subject,
        user_id=user_id,
        scope=PermissionScope.CLIENT,
        client_id=client_id,
        permissions=frozenset(effective),
        entitlements=entitlements,
        is_platform_admin=is_admin,
        via=via,
        membership_ids=tuple(m.id for m in (*tenant_links, *platform_links)),
        denied=frozenset(denied),
    )


def service_principal(name: str, permissions: Iterable[Permission], client_id: str) -> Principal:
    """Principal de serviço interno (workers do pipeline), sem usuário humano por trás."""
    return Principal(
        subject=f"service:{name}",
        user_id=f"service:{name}",
        scope=PermissionScope.CLIENT,
        client_id=client_id,
        permissions=frozenset(permissions),
        via="service",
    )


# --------------------------------------------------------------------------------------


def _permissions_of(memberships: Sequence[Membership]) -> set[Permission]:
    granted: set[Permission] = set()
    for membership in memberships:
        for code in membership.role_codes:
            granted |= get_role(code).permissions
        granted |= set(membership.extra_permissions)
    return granted


def _denied_of(memberships: Sequence[Membership]) -> set[Permission]:
    denied: set[Permission] = set()
    for membership in memberships:
        denied |= set(membership.denied_permissions)
    return denied


def _delegated(platform_permissions: set[Permission]) -> set[Permission]:
    """Traduz permissões de plataforma em permissões dentro do tenant."""
    delegated: set[Permission] = set()
    for permission in platform_permissions:
        delegated |= PLATFORM_TENANT_DELEGATION.get(permission, frozenset())
    return delegated - NEVER_DELEGATED


def _feature_for(permission: Permission) -> Feature | None:
    from vulnai_backoffice.entitlements import FEATURE_GATED_PERMISSIONS

    return FEATURE_GATED_PERMISSIONS.get(permission)
