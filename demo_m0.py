"""Passeio pelo fluxo completo do M0, sem tocar em rede nenhuma.

    py demo_m0.py

Mostra as três barreiras funcionando: RBAC, contrato comercial e gate de escopo.
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

RAIZ = Path(__file__).parent
sys.path[:0] = [
    str(RAIZ / "shared"),
    str(RAIZ / "services" / "authorization"),
    str(RAIZ / "services" / "backoffice"),
]

from vulnai_shared.audit import AuditLog, InMemoryAuditSink  # noqa: E402
from vulnai_shared.clock import utcnow  # noqa: E402
from vulnai_shared.enums import (  # noqa: E402
    ActionClass,
    EngagementStatus,
    ScopeRuleEffect,
    ScopeRuleKind,
)
from vulnai_shared.errors import AuthorizationError  # noqa: E402
from vulnai_shared.models import (  # noqa: E402
    AuthorizationWindow,
    Client,
    Engagement,
    IntensityLimits,
    Scope,
    ScopeRule,
)
from vulnai_authorization import (  # noqa: E402
    AuthorizationService,
    InMemoryEngagementRepository,
    ScopeGuard,
    ScopeTokenSigner,
    generate_secret,
)
from vulnai_backoffice import (  # noqa: E402
    BackofficeService,
    Membership,
    PermissionScope,
    Subscription,
    SubscriptionStatus,
    User,
    UserStatus,
    hash_password,
)
from vulnai_backoffice.errors import BackofficeError  # noqa: E402
from vulnai_backoffice.repository import (  # noqa: E402
    InMemoryClientRepository,
    InMemoryMembershipRepository,
    InMemorySubscriptionRepository,
    InMemoryUserRepository,
)

SENHA = "demonstracao-2026"
AGORA = utcnow()


def secao(titulo: str) -> None:
    print(f"\n{'─' * 74}\n  {titulo}\n{'─' * 74}")


def tentar(descricao: str, funcao) -> None:  # noqa: ANN001
    """Executa e imprime PERMITIDO/NEGADO com o motivo."""
    try:
        funcao()
        print(f"  [PERMITIDO] {descricao}")
    except (AuthorizationError, BackofficeError) as exc:
        print(f"  [ NEGADO  ] {descricao}\n              → {type(exc).__name__}: {exc}")


def main() -> None:
    audit = AuditLog(InMemoryAuditSink())

    # ---------------------------------------------------------------- cenário
    cliente = Client(id="cli-acme", name="ACME S.A.", security_contact="ciso@acme.example")
    escopo = Scope(
        version=1,
        rules=(
            ScopeRule(kind=ScopeRuleKind.DOMAIN, value="acme.example"),
            ScopeRule(kind=ScopeRuleKind.CIDR, value="203.0.113.0/24"),
            ScopeRule(
                kind=ScopeRuleKind.HOSTNAME,
                value="pagamentos.acme.example",
                effect=ScopeRuleEffect.EXCLUDE,
                note="sistema crítico excluído pelo contrato",
            ),
        ),
    )
    engajamento = Engagement(
        id="eng-001",
        client_id=cliente.id,
        name="Avaliação trimestral",
        contract_reference="CT-2026-0041",
        status=EngagementStatus.ACTIVE,
        scope=escopo,
        window=AuthorizationWindow(
            starts_at=AGORA - timedelta(days=1), ends_at=AGORA + timedelta(days=6)
        ),
        limits=IntensityLimits(requests_per_second_per_target=5.0, burst_per_target=3),
    )

    autorizacao = AuthorizationService(
        signer=ScopeTokenSigner(generate_secret()),
        audit_log=audit,
        engagements=InMemoryEngagementRepository([engajamento]),
    )

    backoffice = BackofficeService(
        audit_log=audit,
        users=InMemoryUserRepository(
            [
                User(
                    id="usr-owner",
                    email="ciso@acme.example",
                    full_name="CISO ACME",
                    status=UserStatus.ACTIVE,
                    password_hash=hash_password(SENHA),
                ),
                User(
                    id="usr-leitor",
                    email="auditoria@acme.example",
                    full_name="Auditoria Interna",
                    status=UserStatus.ACTIVE,
                    password_hash=hash_password(SENHA),
                ),
            ]
        ),
        memberships=InMemoryMembershipRepository(
            [
                Membership(
                    user_id="usr-owner",
                    scope=PermissionScope.CLIENT,
                    client_id=cliente.id,
                    role_codes=("client_owner",),
                ),
                Membership(
                    user_id="usr-leitor",
                    scope=PermissionScope.CLIENT,
                    client_id=cliente.id,
                    role_codes=("client_viewer",),
                ),
            ]
        ),
        clients=InMemoryClientRepository([cliente]),
        subscriptions=InMemorySubscriptionRepository(
            [
                Subscription(
                    client_id=cliente.id,
                    plan_code="professional",
                    status=SubscriptionStatus.ACTIVE,
                    starts_at=AGORA - timedelta(days=30),
                )
            ]
        ),
        authorization=autorizacao,
    )

    # -------------------------------------------------------- 1ª barreira: RBAC
    secao("1. RBAC — quem pode pedir")
    owner = backoffice.principal_from_session(
        backoffice.login("ciso@acme.example", SENHA), client_id=cliente.id
    )
    leitor = backoffice.principal_from_session(
        backoffice.login("auditoria@acme.example", SENHA), client_id=cliente.id
    )
    print(f"  {owner.subject}: {len(owner.permissions)} permissões efetivas")
    print(f"  {leitor.subject}: {len(leitor.permissions)} permissões efetivas")

    tentar(
        "leitor emite token de escopo",
        lambda: backoffice.issue_scope_token(
            leitor, engagement_id="eng-001", purpose="tentativa"
        ),
    )

    # ------------------------------------------------- 2ª barreira: entitlement
    secao("2. Contrato comercial — o plano cobre?")
    print(f"  plano vigente: {owner.entitlements.plan_code}")
    tentar(
        "owner pede token INTRUSIVO (plano professional não inclui)",
        lambda: backoffice.issue_scope_token(
            owner,
            engagement_id="eng-001",
            purpose="validação de RCE",
            max_action=ActionClass.INTRUSIVE,
        ),
    )

    token = backoffice.issue_scope_token(
        owner,
        engagement_id="eng-001",
        purpose="varredura trimestral",
        max_action=ActionClass.ACTIVE_NON_INTRUSIVE,
    )
    print(f"  [PERMITIDO] owner emite token não intrusivo → {token[:34]}…")

    # ------------------------------------------------------ 3ª barreira: escopo
    secao("3. Gate de escopo — este alvo, agora, desta forma?")
    guard = ScopeGuard(autorizacao, token, actor=owner.subject, audit_log=audit)

    alvos = [
        "api.acme.example",
        "API.Acme.Example",  # mesma coisa, forma diferente
        "203.0.113.42",
        "pagamentos.acme.example",  # excluído pelo contrato
        "evil-acme.example",  # sufixo sem fronteira de rótulo
        "acme.example.evil.tld",  # domínio contratado como prefixo
        "198.51.100.10",  # fora do CIDR
        "127.0.0.1",  # bloqueado por política
        "169.254.169.254",  # metadados de nuvem
        "http://api.acme.example@evil.tld/",  # userinfo enganoso
    ]
    autorizados, rejeitados = guard.partition(alvos, ActionClass.ACTIVE_NON_INTRUSIVE)
    print(f"\n  autorizados ({len(autorizados)}):")
    for alvo in autorizados:
        print(f"    ✓ {alvo}")
    print(f"\n  rejeitados ({len(rejeitados)}):")
    for rejeicao in rejeitados:
        print(f"    ✗ {rejeicao.raw_target:<38} [{rejeicao.error_code}]")

    secao("4. Execução com auditoria")
    with guard.touch("api.acme.example", ActionClass.ACTIVE_NON_INTRUSIVE, tool="nmap") as alvo:
        print(f"  varrendo {alvo.value} (kind={alvo.kind.value})")

    tentar(
        "limite de intensidade (burst=3, 4ª chamada seguida)",
        lambda: [
            guard.authorize("203.0.113.42", ActionClass.PASSIVE) for _ in range(4)
        ],
    )

    secao("5. Trilha de auditoria")
    for evento in audit:
        alvo = f" alvo={evento.target}" if evento.target else ""
        print(
            f"  #{evento.sequence:02d} {evento.event_type.value:<28} "
            f"{evento.outcome:<9}{alvo}"
        )
    print(f"\n  cadeia verificada: {audit.verify()} eventos íntegros")
    print(f"  head: {audit.head[:32]}…")


if __name__ == "__main__":
    main()
