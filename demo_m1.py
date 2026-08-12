"""Passeio pelo M1 (descoberta + coleta) sobre persistência SQL de verdade.

    py demo_m1.py

Usa SQLite em arquivo por padrão — troque `DATABASE_URL` por uma URL Postgres
(`postgresql+psycopg://usuario:senha@host/banco`) para rodar contra o banco real; nenhum
código muda, só a montagem abaixo. Nenhuma ferramenta externa é executada de verdade:
nmap/subfinder/nuclei/trivy são simulados via `FakeToolRunner` com saída gravada, então
este script não faz nenhuma requisição de rede.
"""

from __future__ import annotations

import os
import sys
from datetime import timedelta
from pathlib import Path

RAIZ = Path(__file__).parent
sys.path[:0] = [
    str(RAIZ / "shared"),
    str(RAIZ / "services" / "authorization"),
    str(RAIZ / "services" / "backoffice"),
    str(RAIZ / "services" / "discovery"),
    str(RAIZ / "services" / "collection"),
]

from vulnai_shared.audit import AuditLog  # noqa: E402
from vulnai_shared.clock import utcnow  # noqa: E402
from vulnai_shared.enums import ActionClass, EngagementStatus, ScopeRuleKind  # noqa: E402
from vulnai_shared.models import (  # noqa: E402
    AuthorizationWindow,
    Client,
    Engagement,
    Scope,
    ScopeRule,
)
from vulnai_authorization import AuthorizationService, ScopeGuard, ScopeTokenSigner  # noqa: E402
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
from vulnai_collection import CollectionService, FakeToolRunner as FakeCollectionRunner, ToolResult as CollectionToolResult  # noqa: E402
from vulnai_discovery import DiscoveryService, FakeToolRunner as FakeDiscoveryRunner, ToolResult as DiscoveryToolResult  # noqa: E402
from vulnai_persistence import (  # noqa: E402
    SqlApiKeyRepository,
    SqlApprovalRepository,
    SqlAssetRepository,
    SqlAuditSink,
    SqlClientRepository,
    SqlEngagementRepository,
    SqlFindingRepository,
    SqlMembershipRepository,
    SqlServiceRepository,
    SqlSessionRepository,
    SqlSubscriptionRepository,
    SqlUserRepository,
    SqlVulnerabilityRepository,
    build_engine,
    build_session_factory,
    create_all,
)

SENHA = "demonstracao-2026"
AGORA = utcnow()
DB_PATH = RAIZ / "demo_m1.db"
FIXTURES = RAIZ / "tests" / "fixtures"


def secao(titulo: str) -> None:
    print(f"\n{'─' * 74}\n  {titulo}\n{'─' * 74}")


def main() -> None:
    DB_PATH.unlink(missing_ok=True)
    database_url = os.environ.get("DATABASE_URL", f"sqlite:///{DB_PATH}")
    engine = build_engine(database_url)
    create_all(engine)
    sessions = build_session_factory(engine)
    print(f"  banco: {database_url}")

    audit = AuditLog(SqlAuditSink(sessions))

    # ---------------------------------------------------------------- cenário
    engagements = SqlEngagementRepository(sessions)
    engagements.save(
        Engagement(
            id="eng-001",
            client_id="cli-acme",
            name="Avaliação trimestral",
            contract_reference="CT-2026-0041",
            status=EngagementStatus.ACTIVE,
            scope=Scope(
                rules=(
                    ScopeRule(kind=ScopeRuleKind.DOMAIN, value="acme.example"),
                    ScopeRule(kind=ScopeRuleKind.CIDR, value="203.0.113.0/24"),
                )
            ),
            window=AuthorizationWindow(starts_at=AGORA - timedelta(days=1), ends_at=AGORA + timedelta(days=6)),
        )
    )

    autorizacao = AuthorizationService(
        signer=ScopeTokenSigner(b"x" * 32),
        audit_log=audit,
        engagements=engagements,
        approvals=SqlApprovalRepository(sessions),
    )

    clients = SqlClientRepository(sessions)
    clients.save(Client(id="cli-acme", name="ACME S.A.", security_contact="ciso@acme.example"))
    users = SqlUserRepository(sessions)
    users.save(
        User(
            id="usr-owner", email="ciso@acme.example", full_name="CISO ACME",
            status=UserStatus.ACTIVE, password_hash=hash_password(SENHA),
        )
    )
    memberships = SqlMembershipRepository(sessions)
    memberships.save(
        Membership(user_id="usr-owner", scope=PermissionScope.CLIENT, client_id="cli-acme", role_codes=("client_owner",))
    )
    subscriptions = SqlSubscriptionRepository(sessions)
    subscriptions.save(
        Subscription(client_id="cli-acme", plan_code="professional", status=SubscriptionStatus.ACTIVE, starts_at=AGORA - timedelta(days=30))
    )

    backoffice = BackofficeService(
        audit_log=audit, users=users, memberships=memberships, clients=clients,
        subscriptions=subscriptions, api_keys=SqlApiKeyRepository(sessions),
        sessions=SqlSessionRepository(sessions), authorization=autorizacao,
    )

    # ------------------------------------------------------------- autenticação
    secao("1. Login + emissão de token (backoffice sobre SQL)")
    owner = backoffice.principal_from_session(
        backoffice.login("ciso@acme.example", SENHA), client_id="cli-acme"
    )
    token = backoffice.issue_scope_token(
        owner, engagement_id="eng-001", purpose="M1 — descoberta e coleta",
        max_action=ActionClass.ACTIVE_NON_INTRUSIVE,
    )
    print(f"  token emitido: {token[:40]}…")

    guard = ScopeGuard(autorizacao, token, actor=owner.subject, audit_log=audit)

    # -------------------------------------------------------------- descoberta
    secao("2. Descoberta de ativos (nmap simulado, gravado em SQL)")
    discovery_runner = FakeDiscoveryRunner()
    discovery_runner.script(
        ("nmap",),
        DiscoveryToolResult(
            command=(), returncode=0,
            stdout=(FIXTURES / "nmap_scan.xml").read_text(encoding="utf-8"), stderr="",
        ),
    )
    discovery = DiscoveryService(
        guard=guard, runner=discovery_runner, client_id="cli-acme", engagement_id="eng-001",
        assets=SqlAssetRepository(sessions), services=SqlServiceRepository(sessions),
    )
    ativo = discovery.scan_host("api.acme.example")
    print(f"  ativo gravado: {ativo.identifier} ({ativo.addresses[0]})")
    for servico in discovery.services_of(ativo.id):
        print(f"    porta {servico.port}/{servico.protocol}: {servico.product} {servico.version}")

    # ---------------------------------------------------------- coleta/enriquecimento
    secao("3. Fingerprint + correlação CVE/NVD + CISA KEV (nuclei simulado)")
    collection_runner = FakeCollectionRunner()
    collection_runner.script(
        ("nuclei",),
        CollectionToolResult(
            command=(), returncode=0,
            stdout=(FIXTURES / "nuclei_output.jsonl").read_text(encoding="utf-8"), stderr="",
        ),
    )
    from vulnai_collection import CveRecord, StaticKevCatalog, StaticNvdCatalog

    nvd = StaticNvdCatalog()
    nvd.add(CveRecord(cve_id="CVE-2021-41773", title="CVE-2021-41773", cvss_score=9.8))
    kev = StaticKevCatalog({"CVE-2021-41773"})

    collection = CollectionService(
        guard=guard, runner=collection_runner, client_id="cli-acme", engagement_id="eng-001",
        findings=SqlFindingRepository(sessions), vulnerabilities=SqlVulnerabilityRepository(sessions),
        nvd=nvd, kev=kev,
    )
    achados = collection.fingerprint_scan("api.acme.example", asset_id=ativo.id)
    for achado in achados:
        kev_marca = ""
        if achado.vulnerability_id:
            vuln = collection._vulnerabilities.get_by_cve("CVE-2021-41773")
            kev_marca = " [CISA KEV]" if vuln and vuln.in_cisa_kev else ""
        print(f"  {achado.severity.value:<9} {achado.title}{kev_marca}")

    # ------------------------------------------------------- prova de persistência
    secao("4. Reabrindo o banco em uma conexão nova (prova de persistência real)")
    sessions2 = build_session_factory(build_engine(database_url))
    reaberto = SqlAssetRepository(sessions2).list_for_engagement("cli-acme", "eng-001")
    print(f"  {len(reaberto)} ativo(s) recuperado(s) de uma sessão nova, sem estado em memória")

    audit_reaberto = AuditLog(SqlAuditSink(sessions2))
    print(f"  cadeia de auditoria: {audit_reaberto.verify()} eventos íntegros, head={audit_reaberto.head[:24]}…")

    if str(DB_PATH) in database_url:
        print(f"\n  arquivo do banco: {DB_PATH}")


if __name__ == "__main__":
    main()
