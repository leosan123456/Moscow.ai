"""API HTTP do backoffice: códigos de status e separação dos dois consoles."""

from __future__ import annotations

import pytest

from vulnai_backoffice.service import BackofficeService

fastapi = pytest.importorskip("fastapi", reason="extra [api] não instalado")
from fastapi.testclient import TestClient  # noqa: E402

from vulnai_backoffice.api import create_app  # noqa: E402

SENHA = "senha-de-teste-123"


@pytest.fixture
def api(backoffice: BackofficeService) -> TestClient:
    return TestClient(create_app(backoffice))


def _login(api: TestClient, email: str) -> dict[str, str]:
    resposta = api.post("/api/auth/login", json={"email": email, "password": SENHA})
    assert resposta.status_code == 200
    return {"Authorization": f"Bearer {resposta.json()['session_token']}"}


def test_login_invalido_retorna_401(api: TestClient) -> None:
    resposta = api.post(
        "/api/auth/login", json={"email": "admin@vulnai.example", "password": "errada-123456"}
    )
    assert resposta.status_code == 401


def test_rota_sem_credencial_retorna_401(api: TestClient) -> None:
    assert api.get("/api/platform/me").status_code == 401


def test_me_de_plataforma_lista_permissoes(api: TestClient) -> None:
    resposta = api.get("/api/platform/me", headers=_login(api, "admin@vulnai.example"))
    corpo = resposta.json()
    assert resposta.status_code == 200
    assert corpo["is_platform_admin"] is True
    assert "platform:client.manage" in corpo["permissions"]


def test_me_de_cliente_mostra_plano_e_cotas(api: TestClient) -> None:
    resposta = api.get(
        "/api/clients/cli-acme/me", headers=_login(api, "ciso@acme.example")
    )
    corpo = resposta.json()
    assert resposta.status_code == 200
    assert corpo["plan_code"] == "professional"
    assert "llm_rag_analyst" in corpo["features"]
    assert corpo["quotas"]["max_users"] == 40


def test_tenant_alheio_retorna_403(api: TestClient) -> None:
    resposta = api.get(
        "/api/clients/cli-globex/me", headers=_login(api, "ciso@acme.example")
    )
    assert resposta.status_code == 403


def test_bloqueio_comercial_retorna_402(api: TestClient) -> None:
    """Falta de plano é 402, não 403: a UI oferece upgrade em vez de 'acesso negado'."""
    resposta = api.post(
        "/api/clients/cli-acme/scope-tokens",
        headers=_login(api, "ciso@acme.example"),
        json={
            "engagement_id": "eng-001",
            "purpose": "validação de RCE",
            "max_action": "intrusive",
        },
    )
    assert resposta.status_code == 402
    assert resposta.json()["feature"] == "intrusive_checks"


def test_falta_de_permissao_retorna_403_com_a_permissao(
    api: TestClient, memberships
) -> None:  # noqa: ANN001
    from vulnai_backoffice import Membership, PermissionScope

    memberships.save(
        Membership(
            id="mb-acme-analista",
            user_id="usr-acme-analista",
            scope=PermissionScope.CLIENT,
            client_id="cli-acme",
            role_codes=("client_viewer",),
        )
    )
    resposta = api.post(
        "/api/clients/cli-acme/scope-tokens",
        headers=_login(api, "analista@acme.example"),
        json={"engagement_id": "eng-001", "purpose": "tentativa"},
    )
    assert resposta.status_code == 403
    assert resposta.json()["permission"] == "scope_token:issue"


def test_emissao_de_token_de_escopo_pelo_console_do_cliente(api: TestClient) -> None:
    resposta = api.post(
        "/api/clients/cli-acme/scope-tokens",
        headers=_login(api, "ciso@acme.example"),
        json={"engagement_id": "eng-001", "purpose": "varredura", "max_action": "passive"},
    )
    assert resposta.status_code == 201
    assert resposta.json()["scope_token"].startswith("vast1.")


def test_chave_de_api_nao_abre_console_de_plataforma(
    api: TestClient, backoffice: BackofficeService, principal_for
) -> None:  # noqa: ANN001
    owner = principal_for("ciso@acme.example", "cli-acme")
    raw, _ = backoffice.create_api_key(owner, name="ci")

    assert api.get("/api/platform/me", headers={"X-API-Key": raw}).status_code == 403
    resposta = api.get("/api/clients/cli-acme/me", headers={"X-API-Key": raw})
    assert resposta.status_code == 200
    assert resposta.json()["client_id"] == "cli-acme"


def test_ciclo_de_vida_da_chave_de_api(api: TestClient) -> None:
    headers = _login(api, "ciso@acme.example")
    criacao = api.post(
        "/api/clients/cli-acme/api-keys", headers=headers, json={"name": "pipeline"}
    )
    assert criacao.status_code == 201
    chave = criacao.json()

    assert api.get("/api/clients/cli-acme/me", headers={"X-API-Key": chave["api_key"]}).status_code == 200

    assert (
        api.delete(
            f"/api/clients/cli-acme/api-keys/{chave['key_id']}", headers=headers
        ).status_code
        == 204
    )
    assert (
        api.get("/api/clients/cli-acme/me", headers={"X-API-Key": chave["api_key"]}).status_code
        == 401
    )


def test_admin_cria_cliente_e_assinatura(api: TestClient) -> None:
    headers = _login(api, "admin@vulnai.example")
    criacao = api.post(
        "/api/platform/clients",
        headers=headers,
        json={"name": "Initech", "security_contact": "sec@initech.example"},
    )
    assert criacao.status_code == 201
    client_id = criacao.json()["id"]

    assinatura = api.put(
        f"/api/platform/clients/{client_id}/subscription",
        headers=headers,
        json={"plan_code": "enterprise", "status": "active"},
    )
    assert assinatura.status_code == 200
    assert assinatura.json()["plan_code"] == "enterprise"


def test_cliente_nao_cria_outro_cliente(api: TestClient) -> None:
    resposta = api.post(
        "/api/platform/clients",
        headers=_login(api, "ciso@acme.example"),
        json={"name": "Empresa Pirata", "security_contact": "x@y.example"},
    )
    assert resposta.status_code == 403


def test_logout_invalida_a_sessao_na_api(api: TestClient) -> None:
    headers = _login(api, "ciso@acme.example")
    assert api.post("/api/auth/logout", headers=headers).status_code == 204
    assert api.get("/api/clients/cli-acme/me", headers=headers).status_code == 401
