"""Camada de persistência: os repositórios SQL precisam se comportar exatamente como os
repositórios em memória que substituem — mesma semântica de upsert, mesmo isolamento de
tenant — só trocando o armazenamento por trás. Roda contra SQLite (ver
`vulnai_persistence/engine.py` sobre por que isso é seguro para o esquema deste projeto).
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from vulnai_shared.audit import AuditLog
from vulnai_shared.clock import FrozenClock
from vulnai_shared.enums import (
    ActionClass,
    AssetCriticality,
    AuditEventType,
    EngagementStatus,
    FindingStatus,
    ScopeRuleKind,
    Severity,
    TargetKind,
)
from vulnai_shared.errors import AuditChainError
from vulnai_shared.models import (
    AuthorizationWindow,
    Asset,
    Client,
    Engagement,
    Finding,
    Scope,
    ScopeRule,
    Service,
    Vulnerability,
)
from vulnai_authorization import AuthorizationService, ScopeGuard, ScopeTokenSigner
from vulnai_backoffice import (
    BackofficeService,
    Membership,
    PermissionScope,
    Subscription,
    SubscriptionStatus,
    User,
    UserStatus,
    hash_password,
)
from vulnai_backoffice.models import ApiKey
from vulnai_discovery import DiscoveryService, FakeToolRunner, ToolResult
from vulnai_persistence import (
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

pytest.importorskip("sqlalchemy", reason="extra [db] não instalado")


@pytest.fixture
def sessions(tmp_path: Path):
    engine = build_engine(f"sqlite:///{tmp_path / 'vulnai_test.db'}")
    create_all(engine)
    return build_session_factory(engine)


# --------------------------------------------------------------------------- autorização


def test_engagement_round_trip_preserva_tipos(sessions, engagement: Engagement) -> None:
    """Enum, datetime timezone-aware e tupla precisam sobreviver ao JSON intacto."""
    repo = SqlEngagementRepository(sessions)
    repo.save(engagement)

    recuperado = repo.get(engagement.id)
    assert recuperado == engagement
    assert recuperado.status is EngagementStatus.ACTIVE
    assert recuperado.window.starts_at.tzinfo is not None
    assert isinstance(recuperado.scope.rules, tuple)


def test_engagement_list_for_client_isola_tenant(sessions, engagement: Engagement) -> None:
    repo = SqlEngagementRepository(sessions)
    repo.save(engagement)
    repo.save(engagement.model_copy(update={"id": "eng-002", "client_id": "cli-outro"}))

    assert [e.id for e in repo.list_for_client("cli-acme")] == ["eng-001"]
    assert [e.id for e in repo.list_for_client("cli-outro")] == ["eng-002"]


def test_engagement_save_atualiza_em_vez_de_duplicar(sessions, engagement: Engagement) -> None:
    repo = SqlEngagementRepository(sessions)
    repo.save(engagement)
    repo.save(engagement.model_copy(update={"status": EngagementStatus.SUSPENDED}))

    assert len(repo.list_for_client("cli-acme")) == 1
    assert repo.get("eng-001").status is EngagementStatus.SUSPENDED


def test_gate_completo_com_repositorios_sql(sessions, clock: FrozenClock, engagement: Engagement) -> None:
    """O gate inteiro (emitir token, autorizar, negar fora de escopo) sobre SQL de verdade."""
    engagements = SqlEngagementRepository(sessions)
    engagements.save(engagement)
    approvals = SqlApprovalRepository(sessions)
    audit = AuditLog(SqlAuditSink(sessions), clock=clock)

    service = AuthorizationService(
        signer=ScopeTokenSigner(b"x" * 32, clock=clock),
        audit_log=audit,
        engagements=engagements,
        approvals=approvals,
        clock=clock,
    )
    token = service.issue_scope_token(
        "eng-001", operator="analista@vulnai.example", purpose="teste sql"
    )

    assert service.authorize(token, "api.acme.example", ActionClass.PASSIVE).allowed
    from vulnai_shared.errors import OutOfScopeError

    with pytest.raises(OutOfScopeError):
        service.authorize(token, "evil.tld", ActionClass.PASSIVE)

    assert audit.verify() == len(list(audit))


# ---------------------------------------------------------------------------- backoffice


def test_client_repository_round_trip(sessions, client: Client) -> None:
    repo = SqlClientRepository(sessions)
    repo.save(client)
    assert repo.get(client.id) == client
    assert [c.id for c in repo.list_all()] == [client.id]


def test_user_lookup_por_email_e_case_insensitive_na_normalizacao(sessions) -> None:
    repo = SqlUserRepository(sessions)
    user = User(email="CISO@Acme.Example", full_name="CISO", password_hash=hash_password("x" * 12))
    repo.save(user)

    encontrado = repo.get_by_email("ciso@acme.example")
    assert encontrado is not None
    assert encontrado.id == user.id


def test_user_email_unico_e_reforcado_pelo_banco(sessions) -> None:
    repo = SqlUserRepository(sessions)
    repo.save(User(id="u1", email="dup@acme.example", full_name="Um"))

    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        repo.save(User(id="u2", email="dup@acme.example", full_name="Outro"))


def test_membership_list_for_client(sessions) -> None:
    repo = SqlMembershipRepository(sessions)
    repo.save(
        Membership(
            id="m1", user_id="u1", scope=PermissionScope.CLIENT, client_id="cli-acme",
            role_codes=("client_owner",),
        )
    )
    repo.save(
        Membership(
            id="m2", user_id="u2", scope=PermissionScope.CLIENT, client_id="cli-outro",
            role_codes=("client_owner",),
        )
    )
    assert [m.id for m in repo.list_for_client("cli-acme")] == ["m1"]
    assert repo.get("m1").role_codes == ("client_owner",)


def test_subscription_upsert_por_cliente(sessions, clock: FrozenClock) -> None:
    repo = SqlSubscriptionRepository(sessions)
    repo.save(
        Subscription(
            client_id="cli-acme", plan_code="essential", status=SubscriptionStatus.ACTIVE,
            starts_at=clock(),
        )
    )
    repo.save(
        Subscription(
            client_id="cli-acme", plan_code="enterprise", status=SubscriptionStatus.ACTIVE,
            starts_at=clock(),
        )
    )
    assert repo.get_for_client("cli-acme").plan_code == "enterprise"


def test_api_key_round_trip_e_list_for_client(sessions) -> None:
    repo = SqlApiKeyRepository(sessions)
    repo.save(
        ApiKey(
            membership_id="m1", client_id="cli-acme", name="ci", key_id="abc12345",
            secret_hash="h" * 64,
        )
    )
    assert repo.get_by_key_id("abc12345") is not None
    assert len(repo.list_for_client("cli-acme")) == 1
    assert repo.list_for_client("cli-outro") == []


def test_session_round_trip(sessions, clock: FrozenClock) -> None:
    from vulnai_backoffice.models import Session as BackofficeSession

    repo = SqlSessionRepository(sessions)
    repo.save(
        BackofficeSession(
            user_id="u1", token_hash="hash123", issued_at=clock(),
            expires_at=clock() + timedelta(hours=1),
        )
    )
    encontrada = repo.get_by_token_hash("hash123")
    assert encontrada is not None
    assert encontrada.user_id == "u1"


def test_backoffice_completo_com_repositorios_sql(sessions, clock: FrozenClock) -> None:
    """Login -> resolução de principal -> emissão de token, tudo sobre SQL."""
    scope = Scope(rules=(ScopeRule(kind=ScopeRuleKind.DOMAIN, value="acme.example"),))
    engagement = Engagement(
        id="eng-001", client_id="cli-acme", name="Eng", contract_reference="CT-1",
        status=EngagementStatus.ACTIVE, scope=scope,
        window=AuthorizationWindow(starts_at=clock() - timedelta(days=1), ends_at=clock() + timedelta(days=1)),
    )
    engagements = SqlEngagementRepository(sessions)
    engagements.save(engagement)

    audit = AuditLog(SqlAuditSink(sessions), clock=clock)
    auth_service = AuthorizationService(
        signer=ScopeTokenSigner(b"y" * 32, clock=clock), audit_log=audit,
        engagements=engagements, clock=clock,
    )

    clients = SqlClientRepository(sessions)
    clients.save(Client(id="cli-acme", name="ACME"))
    users = SqlUserRepository(sessions)
    users.save(
        User(id="u1", email="ciso@acme.example", full_name="CISO", status=UserStatus.ACTIVE,
             password_hash=hash_password("senha-de-teste-123"))
    )
    memberships = SqlMembershipRepository(sessions)
    memberships.save(
        Membership(id="m1", user_id="u1", scope=PermissionScope.CLIENT, client_id="cli-acme",
                   role_codes=("client_owner",))
    )
    subscriptions = SqlSubscriptionRepository(sessions)
    subscriptions.save(
        Subscription(client_id="cli-acme", plan_code="enterprise", status=SubscriptionStatus.ACTIVE,
                     starts_at=clock() - timedelta(days=1))
    )

    backoffice = BackofficeService(
        audit_log=audit, users=users, memberships=memberships, clients=clients,
        subscriptions=subscriptions, api_keys=SqlApiKeyRepository(sessions),
        sessions=SqlSessionRepository(sessions), authorization=auth_service, clock=clock,
    )

    token = backoffice.login("ciso@acme.example", "senha-de-teste-123")
    principal = backoffice.principal_from_session(token, client_id="cli-acme")
    assert principal.client_id == "cli-acme"
    assert principal.entitlements.plan_code == "enterprise"

    scope_token = backoffice.issue_scope_token(
        principal, engagement_id="eng-001", purpose="teste"
    )
    assert scope_token.startswith("vast1.")


# ---------------------------------------------------------------------------- descoberta


def test_asset_upsert_funde_em_vez_de_duplicar(sessions, clock: FrozenClock) -> None:
    repo = SqlAssetRepository(sessions)
    base = Asset(
        client_id="cli-acme", engagement_id="eng-001", kind=TargetKind.HOSTNAME,
        identifier="api.acme.example", hostnames=("api.acme.example",),
        first_seen_at=clock(), last_seen_at=clock(),
    )
    primeiro = repo.upsert(base)
    segundo = repo.upsert(
        base.model_copy(update={"addresses": ("203.0.113.10",), "last_seen_at": clock() + timedelta(minutes=5)})
    )

    assert primeiro.id == segundo.id
    assert segundo.addresses == ("203.0.113.10",)
    assert len(repo.list_for_engagement("cli-acme", "eng-001")) == 1


def test_asset_identifier_unico_por_cliente(sessions, clock: FrozenClock) -> None:
    """Dois tenants podem ter o mesmo identifier (nomes coincidem); um só não pode duplicar."""
    repo = SqlAssetRepository(sessions)
    a1 = Asset(
        client_id="cli-acme", engagement_id="eng-001", kind=TargetKind.HOSTNAME,
        identifier="api.example.com", first_seen_at=clock(), last_seen_at=clock(),
    )
    a2 = a1.model_copy(update={"client_id": "cli-outro", "id": "outro-id"})
    repo.upsert(a1)
    repo.upsert(a2)
    assert repo.get_by_identifier("cli-acme", "api.example.com").client_id == "cli-acme"
    assert repo.get_by_identifier("cli-outro", "api.example.com").client_id == "cli-outro"


def test_service_upsert_preenche_lacunas_sem_apagar_dado_anterior(sessions) -> None:
    repo = SqlServiceRepository(sessions)
    asset_id = "asset-1"
    repo.upsert(Service(client_id="cli-acme", asset_id=asset_id, port=443, protocol="tcp", product="nginx"))
    atualizado = repo.upsert(
        Service(client_id="cli-acme", asset_id=asset_id, port=443, protocol="tcp", version="1.24.0")
    )
    assert atualizado.product == "nginx"
    assert atualizado.version == "1.24.0"
    assert len(repo.list_for_asset("cli-acme", asset_id)) == 1


def test_discovery_service_ponta_a_ponta_com_sql(
    sessions, service: AuthorizationService, token: str, audit: AuditLog
) -> None:
    guard = ScopeGuard(service, token, actor="worker", audit_log=audit)
    runner = FakeToolRunner()
    nmap_xml = (Path(__file__).parent / "fixtures" / "nmap_scan.xml").read_text(encoding="utf-8")
    runner.script(("nmap",), ToolResult(command=(), returncode=0, stdout=nmap_xml, stderr=""))

    discovery = DiscoveryService(
        guard=guard, runner=runner, client_id="cli-acme", engagement_id="eng-001",
        assets=SqlAssetRepository(sessions), services=SqlServiceRepository(sessions),
    )
    asset = discovery.scan_host("api.acme.example")
    assert asset.addresses == ("203.0.113.10",)
    assert len(discovery.services_of(asset.id)) == 1


# -------------------------------------------------------------------------------- coleta


def test_vulnerability_upsert_acumula_kev_e_cvss(sessions) -> None:
    repo = SqlVulnerabilityRepository(sessions)
    repo.upsert(Vulnerability(cve_id="CVE-2021-41773", title="CVE-2021-41773", in_cisa_kev=False))
    atualizado = repo.upsert(
        Vulnerability(cve_id="CVE-2021-41773", title="CVE-2021-41773", cvss_score=9.8, in_cisa_kev=True)
    )
    assert atualizado.cvss_score == 9.8
    assert atualizado.in_cisa_kev is True
    assert repo.get_by_cve("CVE-2021-41773").cvss_score == 9.8


def test_finding_set_status_preserva_triagem_apos_rescan(sessions) -> None:
    repo = SqlFindingRepository(sessions)
    achado = repo.upsert(
        Finding(
            client_id="cli-acme", engagement_id="eng-001", asset_id="asset-1",
            title="Path Traversal", severity=Severity.CRITICAL,
        )
    )
    repo.set_status(achado.id, FindingStatus.FALSE_POSITIVE)

    rescan = repo.upsert(
        Finding(
            client_id="cli-acme", engagement_id="eng-001", asset_id="asset-1",
            title="Path Traversal", severity=Severity.CRITICAL, evidence="novo scan",
        )
    )
    assert rescan.id == achado.id
    assert rescan.status is FindingStatus.FALSE_POSITIVE
    assert rescan.evidence == "novo scan"


def test_finding_set_status_de_id_inexistente(sessions) -> None:
    repo = SqlFindingRepository(sessions)
    with pytest.raises(KeyError):
        repo.set_status("nao-existe", FindingStatus.FALSE_POSITIVE)


# -------------------------------------------------------------------------------- auditoria


def test_audit_sink_preserva_a_cadeia_de_hash(sessions, clock: FrozenClock) -> None:
    log = AuditLog(SqlAuditSink(sessions), clock=clock)
    log.record(AuditEventType.TOKEN_ISSUED, actor="a", outcome="issued", client_id="cli-acme")
    log.record(AuditEventType.AUTHORIZATION_ALLOWED, actor="a", outcome="allow", target="x.example")

    assert log.verify() == 2


def test_audit_sink_retomado_por_um_segundo_processo(sessions, clock: FrozenClock) -> None:
    primeiro = AuditLog(SqlAuditSink(sessions), clock=clock)
    primeiro.record(AuditEventType.TOKEN_ISSUED, actor="a", outcome="issued")

    segundo = AuditLog(SqlAuditSink(sessions), clock=clock)
    assert segundo.head == primeiro.head
    terceiro_evento = segundo.record(AuditEventType.REPORT_GENERATED, actor="a", outcome="ok")

    assert terceiro_evento.sequence == 2
    assert segundo.verify() == 2


def test_audit_sink_detecta_adulteracao_direta_no_banco(sessions, clock: FrozenClock) -> None:
    from vulnai_persistence.orm import AuditEventRow

    log = AuditLog(SqlAuditSink(sessions), clock=clock)
    log.record(AuditEventType.ASSET_TOUCHED, actor="a", outcome="ok", target="a.example")
    log.record(AuditEventType.ASSET_TOUCHED, actor="a", outcome="ok", target="b.example")

    with sessions() as session:
        row = session.get(AuditEventRow, 1)
        row.payload = {**row.payload, "target": "algo-inocente.example"}
        session.commit()

    with pytest.raises(AuditChainError):
        AuditLog(SqlAuditSink(sessions), clock=clock).verify()
