"""Fixtures compartilhadas: um engajamento realista, relógio congelado e o gate montado."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from vulnai_shared.audit import AuditLog, InMemoryAuditSink
from vulnai_shared.clock import FrozenClock
from vulnai_shared.enums import (
    ActionClass,
    EngagementStatus,
    ScopeRuleEffect,
    ScopeRuleKind,
)
from vulnai_shared.models import (
    AuthorizationWindow,
    Client,
    Engagement,
    IntensityLimits,
    IntrusiveAuthorization,
    Scope,
    ScopeRule,
)
from vulnai_authorization import (
    AuthorizationService,
    InMemoryApprovalRepository,
    InMemoryEngagementRepository,
    ScopeTokenSigner,
    TokenBucketLimiter,
)
from vulnai_backoffice import (
    BackofficeService,
    Membership,
    PermissionScope,
    Principal,
    Subscription,
    SubscriptionStatus,
    User,
    UserStatus,
    hash_password,
)
from vulnai_backoffice.repository import (
    InMemoryClientRepository,
    InMemoryMembershipRepository,
    InMemorySubscriptionRepository,
    InMemoryUserRepository,
)

NOW = datetime(2026, 3, 10, 12, 0, tzinfo=UTC)
TEST_SECRET = b"x" * 32


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock(NOW)


@pytest.fixture
def client() -> Client:
    return Client(id="cli-acme", name="ACME S.A.", security_contact="ciso@acme.example")


@pytest.fixture
def scope() -> Scope:
    return Scope(
        version=3,
        rules=(
            ScopeRule(kind=ScopeRuleKind.CIDR, value="203.0.113.0/24"),
            ScopeRule(kind=ScopeRuleKind.DOMAIN, value="acme.example"),
            ScopeRule(
                kind=ScopeRuleKind.DOMAIN,
                value="lab.acme.example",
                max_action=ActionClass.INTRUSIVE,
                note="ambiente de laboratório, liberado para checagem intrusiva",
            ),
            # Produção de pagamentos fica fora do contrato, mesmo estando sob o domínio.
            ScopeRule(
                kind=ScopeRuleKind.HOSTNAME,
                value="pagamentos.acme.example",
                effect=ScopeRuleEffect.EXCLUDE,
                note="sistema crítico excluído pelas regras de engajamento",
            ),
            ScopeRule(
                kind=ScopeRuleKind.IP,
                value="203.0.113.9",
                effect=ScopeRuleEffect.EXCLUDE,
                note="gateway do cliente",
            ),
        ),
    )


@pytest.fixture
def engagement(client: Client, scope: Scope) -> Engagement:
    return Engagement(
        id="eng-001",
        client_id=client.id,
        name="Avaliação trimestral Q1",
        contract_reference="CT-2026-0041",
        status=EngagementStatus.ACTIVE,
        scope=scope,
        window=AuthorizationWindow(
            starts_at=NOW - timedelta(days=1),
            ends_at=NOW + timedelta(days=6),
        ),
        limits=IntensityLimits(requests_per_second_per_target=2.0, burst_per_target=3),
        max_action=ActionClass.ACTIVE_NON_INTRUSIVE,
    )


@pytest.fixture
def intrusive_engagement(engagement: Engagement) -> Engagement:
    """Mesma engagement, com opt-in intrusivo registrado e vigente."""
    return engagement.model_copy(
        update={
            "max_action": ActionClass.INTRUSIVE,
            "intrusive_authorization": IntrusiveAuthorization(
                approved_by="ciso@acme.example",
                approval_reference="CT-2026-0041-ADENDO-2",
                window=AuthorizationWindow(
                    starts_at=NOW - timedelta(hours=1),
                    ends_at=NOW + timedelta(hours=4),
                ),
                justification="Validação de RCE em ambiente de laboratório isolado.",
            ),
        }
    )


@pytest.fixture
def audit(clock: FrozenClock) -> AuditLog:
    return AuditLog(InMemoryAuditSink(), clock=clock)


@pytest.fixture
def signer(clock: FrozenClock) -> ScopeTokenSigner:
    return ScopeTokenSigner(TEST_SECRET, clock=clock)


@pytest.fixture
def engagements(engagement: Engagement) -> InMemoryEngagementRepository:
    return InMemoryEngagementRepository([engagement])


@pytest.fixture
def approvals() -> InMemoryApprovalRepository:
    return InMemoryApprovalRepository()


@pytest.fixture
def service(
    signer: ScopeTokenSigner,
    audit: AuditLog,
    engagements: InMemoryEngagementRepository,
    approvals: InMemoryApprovalRepository,
    clock: FrozenClock,
) -> AuthorizationService:
    return AuthorizationService(
        signer=signer,
        audit_log=audit,
        engagements=engagements,
        approvals=approvals,
        limiter=TokenBucketLimiter(clock=clock),
        clock=clock,
    )


@pytest.fixture
def token(service: AuthorizationService) -> str:
    return service.issue_scope_token(
        "eng-001",
        operator="analista@vulnai.example",
        purpose="descoberta de ativos",
        max_action=ActionClass.ACTIVE_NON_INTRUSIVE,
    )


# ======================================================================================
# Backoffice: dois tenants, quatro perfis e dois planos diferentes.
# ======================================================================================

SENHA = "senha-de-teste-123"


@pytest.fixture
def clients(client: Client) -> InMemoryClientRepository:
    return InMemoryClientRepository([client, Client(id="cli-globex", name="Globex Ltda.")])


@pytest.fixture
def users() -> InMemoryUserRepository:
    def _user(user_id: str, email: str, nome: str) -> User:
        return User(
            id=user_id,
            email=email,
            full_name=nome,
            status=UserStatus.ACTIVE,
            password_hash=hash_password(SENHA),
        )

    return InMemoryUserRepository(
        [
            _user("usr-admin", "admin@vulnai.example", "Admin Global"),
            _user("usr-comercial", "comercial@vulnai.example", "Time Comercial"),
            _user("usr-acme-owner", "ciso@acme.example", "CISO ACME"),
            _user("usr-acme-analista", "analista@acme.example", "Analista ACME"),
            _user("usr-globex-owner", "ciso@globex.example", "CISO Globex"),
        ]
    )


@pytest.fixture
def memberships() -> InMemoryMembershipRepository:
    return InMemoryMembershipRepository(
        [
            Membership(
                id="mb-admin",
                user_id="usr-admin",
                scope=PermissionScope.PLATFORM,
                role_codes=("platform_admin",),
            ),
            Membership(
                id="mb-comercial",
                user_id="usr-comercial",
                scope=PermissionScope.PLATFORM,
                role_codes=("platform_commercial",),
            ),
            Membership(
                id="mb-acme-owner",
                user_id="usr-acme-owner",
                scope=PermissionScope.CLIENT,
                client_id="cli-acme",
                role_codes=("client_owner",),
            ),
            Membership(
                id="mb-acme-analista",
                user_id="usr-acme-analista",
                scope=PermissionScope.CLIENT,
                client_id="cli-acme",
                role_codes=("client_analyst",),
            ),
            Membership(
                id="mb-globex-owner",
                user_id="usr-globex-owner",
                scope=PermissionScope.CLIENT,
                client_id="cli-globex",
                role_codes=("client_owner",),
            ),
        ]
    )


@pytest.fixture
def subscriptions(clock: FrozenClock) -> InMemorySubscriptionRepository:
    return InMemorySubscriptionRepository(
        [
            Subscription(
                client_id="cli-acme",
                plan_code="professional",
                status=SubscriptionStatus.ACTIVE,
                starts_at=NOW - timedelta(days=30),
            ),
            Subscription(
                client_id="cli-globex",
                plan_code="essential",
                status=SubscriptionStatus.ACTIVE,
                starts_at=NOW - timedelta(days=10),
            ),
        ]
    )


@pytest.fixture
def backoffice(
    audit: AuditLog,
    users: InMemoryUserRepository,
    memberships: InMemoryMembershipRepository,
    clients: InMemoryClientRepository,
    subscriptions: InMemorySubscriptionRepository,
    service: AuthorizationService,
    clock: FrozenClock,
) -> BackofficeService:
    return BackofficeService(
        audit_log=audit,
        users=users,
        memberships=memberships,
        clients=clients,
        subscriptions=subscriptions,
        authorization=service,
        clock=clock,
    )


@pytest.fixture
def principal_for(backoffice: BackofficeService):
    """Faz login e resolve o principal no tenant pedido (`None` = console de plataforma)."""

    def _resolve(email: str, client_id: str | None = None) -> Principal:
        token = backoffice.login(email, SENHA)
        return backoffice.principal_from_session(token, client_id=client_id)

    return _resolve
