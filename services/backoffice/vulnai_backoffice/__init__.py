"""Backoffice: gestão de acesso (RBAC) e camada comercial (planos e cotas).

Dois consoles sobre o mesmo serviço:

* **Console de plataforma** (`client_id=None`) — nosso time. Administra clientes,
  usuários, papéis, planos e assinaturas.
* **Console do cliente** (`client_id=<tenant>`) — o contratante. Enxerga e opera
  somente o próprio tenant.
"""

from vulnai_backoffice.credentials import generate_api_key, hash_password, verify_password
from vulnai_backoffice.entitlements import (
    ENTERPRISE,
    ESSENTIAL,
    PLAN_CATALOG,
    PROFESSIONAL,
    UNLIMITED,
    Entitlements,
    Feature,
    Plan,
    Quota,
    Subscription,
    SubscriptionStatus,
    resolve_entitlements,
)
from vulnai_backoffice.errors import (
    AuthenticationError,
    BackofficeError,
    EntitlementError,
    FeatureNotContractedError,
    NotFoundError,
    PermissionDeniedError,
    QuotaExceededError,
    SubscriptionInactiveError,
    TenantAccessError,
    UserAlreadyExistsError,
)
from vulnai_backoffice.models import (
    ApiKey,
    Membership,
    MembershipStatus,
    Session,
    User,
    UserStatus,
)
from vulnai_backoffice.permissions import (
    BUILTIN_ROLES,
    Permission,
    PermissionScope,
    Role,
    get_role,
    roles_for_scope,
)
from vulnai_backoffice.rbac import Principal, resolve_principal, service_principal
from vulnai_backoffice.repository import (
    InMemoryApiKeyRepository,
    InMemoryClientRepository,
    InMemoryMembershipRepository,
    InMemorySessionRepository,
    InMemorySubscriptionRepository,
    InMemoryUserRepository,
)
from vulnai_backoffice.service import BackofficeService

__all__ = [
    "BUILTIN_ROLES",
    "ENTERPRISE",
    "ESSENTIAL",
    "PLAN_CATALOG",
    "PROFESSIONAL",
    "UNLIMITED",
    "ApiKey",
    "AuthenticationError",
    "BackofficeError",
    "BackofficeService",
    "Entitlements",
    "EntitlementError",
    "Feature",
    "FeatureNotContractedError",
    "InMemoryApiKeyRepository",
    "InMemoryClientRepository",
    "InMemoryMembershipRepository",
    "InMemorySessionRepository",
    "InMemorySubscriptionRepository",
    "InMemoryUserRepository",
    "Membership",
    "MembershipStatus",
    "NotFoundError",
    "Permission",
    "PermissionDeniedError",
    "PermissionScope",
    "Plan",
    "Principal",
    "Quota",
    "QuotaExceededError",
    "Role",
    "Session",
    "Subscription",
    "SubscriptionInactiveError",
    "SubscriptionStatus",
    "TenantAccessError",
    "User",
    "UserAlreadyExistsError",
    "UserStatus",
    "generate_api_key",
    "get_role",
    "hash_password",
    "resolve_entitlements",
    "resolve_principal",
    "roles_for_scope",
    "service_principal",
    "verify_password",
]
