"""API HTTP do backoffice (FastAPI).

Dois grupos de rotas sobre o mesmo `BackofficeService`:

* `/api/platform/*` — console de plataforma. Exige vínculo `platform:*`.
* `/api/clients/{client_id}/*` — console do cliente. O `client_id` da URL é o tenant
  ativo, e o principal é resolvido **para aquele tenant**: pedir um tenant a que a pessoa
  não pertence já falha na resolução, antes de qualquer handler tocar em dados.

Autenticação por `Authorization: Bearer <sessão>` ou `X-API-Key: vak_...`.

Dependência opcional: só importe este módulo se `fastapi` estiver instalado
(`pip install -e .[api]`).

Nota: este módulo **não** usa `from __future__ import annotations`. Os aliases de
dependência (`PlatformPrincipal`, `ClientPrincipal`) são criados dentro de `create_app`,
e com anotações adiadas o FastAPI não conseguiria resolvê-los — trataria cada principal
como query param e devolveria 422 em toda rota autenticada.
"""

from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Path, Request, status
from pydantic import BaseModel, Field

from vulnai_shared.enums import ActionClass
from vulnai_shared.errors import AuthorizationError
from vulnai_backoffice.entitlements import Feature, Quota, SubscriptionStatus
from vulnai_backoffice.errors import (
    AuthenticationError,
    EntitlementError,
    NotFoundError,
    PermissionDeniedError,
    UserAlreadyExistsError,
)
from vulnai_backoffice.permissions import (
    Permission,
    PermissionScope,
    roles_for_scope,
)
from vulnai_backoffice.rbac import Principal
from vulnai_backoffice.service import BackofficeService


# --------------------------------------------------------------------------------------
# Contratos de entrada/saída
# --------------------------------------------------------------------------------------


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    session_token: str


class MeResponse(BaseModel):
    subject: str
    scope: PermissionScope
    client_id: str | None
    is_platform_admin: bool
    permissions: list[str]
    plan_code: str | None = None
    features: list[str] = Field(default_factory=list)
    quotas: dict[str, int] = Field(default_factory=dict)


class CreateClientRequest(BaseModel):
    name: str
    security_contact: str


class SetSubscriptionRequest(BaseModel):
    plan_code: str
    status: SubscriptionStatus = SubscriptionStatus.ACTIVE
    extra_features: list[Feature] = Field(default_factory=list)
    excluded_features: list[Feature] = Field(default_factory=list)
    quota_overrides: dict[Quota, int] = Field(default_factory=dict)


class InviteUserRequest(BaseModel):
    email: str
    full_name: str
    role_codes: list[str]


class CreateApiKeyRequest(BaseModel):
    name: str


class CreateApiKeyResponse(BaseModel):
    #: Só aparece aqui, uma única vez. O servidor guarda apenas o hash.
    api_key: str
    key_id: str


class IssueScopeTokenRequest(BaseModel):
    engagement_id: str
    purpose: str
    max_action: ActionClass = ActionClass.PASSIVE


class ScopeTokenResponse(BaseModel):
    scope_token: str


# --------------------------------------------------------------------------------------


def create_app(backoffice: BackofficeService) -> FastAPI:
    """Monta a aplicação sobre uma instância já configurada do serviço."""
    app = FastAPI(
        title="vuln-ai-platform — Backoffice",
        description="Gestão de acesso, planos e emissão de tokens de escopo.",
        version="0.1.0",
    )
    app.state.backoffice = backoffice

    # ----------------------------------------------------------- dependências
    def _credentials(
        authorization: Annotated[str | None, Header()] = None,
        x_api_key: Annotated[str | None, Header()] = None,
    ) -> tuple[str, str]:
        if x_api_key:
            return "api_key", x_api_key
        if authorization and authorization.lower().startswith("bearer "):
            return "session", authorization[7:].strip()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="credencial ausente",
            headers={"WWW-Authenticate": "Bearer"},
        )

    def platform_principal(
        credentials: Annotated[tuple[str, str], Depends(_credentials)],
    ) -> Principal:
        """Principal do console de plataforma (sem tenant ativo)."""
        kind, value = credentials
        if kind == "api_key":
            # Chave de API é sempre de tenant; não abre o console de plataforma.
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="chave de API não acessa o console de plataforma",
            )
        return backoffice.principal_from_session(value)

    def client_principal(
        client_id: Annotated[str, Path()],
        credentials: Annotated[tuple[str, str], Depends(_credentials)],
    ) -> Principal:
        """Principal já resolvido **dentro** do tenant da URL."""
        kind, value = credentials
        if kind == "api_key":
            principal = backoffice.principal_from_api_key(value)
            principal.require_client(client_id)
            return principal
        return backoffice.principal_from_session(value, client_id=client_id)

    PlatformPrincipal = Annotated[Principal, Depends(platform_principal)]
    ClientPrincipal = Annotated[Principal, Depends(client_principal)]

    # ------------------------------------------------- tradução de erro -> HTTP
    @app.exception_handler(AuthenticationError)
    async def _auth_error(_: Request, exc: AuthenticationError) -> Any:
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=401, content={"detail": str(exc)})

    @app.exception_handler(PermissionDeniedError)
    async def _denied(_: Request, exc: PermissionDeniedError) -> Any:
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=403,
            content={"detail": str(exc), "permission": getattr(exc, "permission", None)},
        )

    @app.exception_handler(EntitlementError)
    async def _entitlement(_: Request, exc: EntitlementError) -> Any:
        from fastapi.responses import JSONResponse

        # 402: o bloqueio é comercial, não de autorização. A UI usa isso para oferecer
        # upgrade em vez de mostrar "acesso negado".
        return JSONResponse(
            status_code=402,
            content={
                "detail": str(exc),
                "feature": getattr(exc, "feature", None),
                "quota": getattr(exc, "quota", None),
                "limit": getattr(exc, "limit", None),
            },
        )

    @app.exception_handler(AuthorizationError)
    async def _scope_denied(_: Request, exc: AuthorizationError) -> Any:
        from fastapi.responses import JSONResponse

        from vulnai_authorization import error_code_for

        return JSONResponse(
            status_code=403, content={"detail": str(exc), "error_code": error_code_for(exc)}
        )

    @app.exception_handler(NotFoundError)
    async def _not_found(_: Request, exc: NotFoundError) -> Any:
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(UserAlreadyExistsError)
    async def _conflict(_: Request, exc: UserAlreadyExistsError) -> Any:
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=409, content={"detail": str(exc)})

    # ------------------------------------------------------------------ sessão
    @app.post("/api/auth/login", response_model=LoginResponse)
    def login(payload: LoginRequest, request: Request) -> LoginResponse:
        token = backoffice.login(
            payload.email,
            payload.password,
            ip_address=request.client.host if request.client else None,
        )
        return LoginResponse(session_token=token)

    @app.post("/api/auth/logout", status_code=204)
    def logout(credentials: Annotated[tuple[str, str], Depends(_credentials)]) -> None:
        kind, value = credentials
        if kind == "session":
            backoffice.logout(value)

    @app.get("/api/platform/me", response_model=MeResponse)
    def platform_me(principal: PlatformPrincipal) -> MeResponse:
        return _me(principal)

    @app.get("/api/clients/{client_id}/me", response_model=MeResponse)
    def client_me(principal: ClientPrincipal) -> MeResponse:
        return _me(principal)

    # -------------------------------------------------- console de plataforma
    @app.get("/api/platform/roles")
    def list_platform_roles(principal: PlatformPrincipal) -> list[dict[str, Any]]:
        principal.require(Permission.PLATFORM_ROLE_MANAGE)
        return [_role_json(r) for r in roles_for_scope(PermissionScope.PLATFORM)]

    @app.get("/api/platform/client-roles")
    def list_client_roles(principal: PlatformPrincipal) -> list[dict[str, Any]]:
        principal.require(Permission.PLATFORM_CLIENT_MANAGE)
        return [_role_json(r) for r in roles_for_scope(PermissionScope.CLIENT)]

    @app.post("/api/platform/clients", status_code=201)
    def create_client(
        payload: CreateClientRequest, principal: PlatformPrincipal
    ) -> dict[str, str]:
        client = backoffice.create_client(
            principal, name=payload.name, security_contact=payload.security_contact
        )
        return {"id": client.id, "name": client.name}

    @app.put("/api/platform/clients/{client_id}/subscription")
    def set_subscription(
        client_id: str, payload: SetSubscriptionRequest, principal: PlatformPrincipal
    ) -> dict[str, Any]:
        subscription = backoffice.set_subscription(
            principal,
            client_id=client_id,
            plan_code=payload.plan_code,
            status=payload.status,
            extra_features=frozenset(payload.extra_features),
            excluded_features=frozenset(payload.excluded_features),
            quota_overrides=dict(payload.quota_overrides),
        )
        return {
            "id": subscription.id,
            "client_id": subscription.client_id,
            "plan_code": subscription.plan_code,
            "status": subscription.status.value,
        }

    # ------------------------------------------------------ console do cliente
    @app.get("/api/clients/{client_id}/entitlements")
    def entitlements(client_id: str, principal: ClientPrincipal) -> dict[str, Any]:
        principal.require(Permission.CLIENT_BILLING_READ)
        ent = backoffice.entitlements_for(client_id)
        return {
            "plan_code": ent.plan_code,
            "status": ent.status.value if ent.status else None,
            "features": sorted(f.value for f in ent.features),
            "quotas": {q.value: v for q, v in ent.quotas.items()},
        }

    @app.post("/api/clients/{client_id}/users", status_code=201)
    def invite_user(
        client_id: str, payload: InviteUserRequest, principal: ClientPrincipal
    ) -> dict[str, Any]:
        user, membership = backoffice.invite_client_user(
            principal,
            client_id=client_id,
            email=payload.email,
            full_name=payload.full_name,
            role_codes=tuple(payload.role_codes),
        )
        return {
            "user_id": user.id,
            "email": user.email,
            "membership_id": membership.id,
            "roles": list(membership.role_codes),
        }

    @app.delete("/api/clients/{client_id}/memberships/{membership_id}", status_code=204)
    def revoke_membership(
        client_id: str, membership_id: str, principal: ClientPrincipal
    ) -> None:
        backoffice.revoke_membership(principal, membership_id=membership_id)

    @app.post("/api/clients/{client_id}/api-keys", status_code=201)
    def create_api_key(
        client_id: str, payload: CreateApiKeyRequest, principal: ClientPrincipal
    ) -> CreateApiKeyResponse:
        raw, api_key = backoffice.create_api_key(principal, name=payload.name)
        return CreateApiKeyResponse(api_key=raw, key_id=api_key.key_id)

    @app.delete("/api/clients/{client_id}/api-keys/{key_id}", status_code=204)
    def revoke_api_key(client_id: str, key_id: str, principal: ClientPrincipal) -> None:
        backoffice.revoke_api_key(principal, key_id=key_id)

    @app.post("/api/clients/{client_id}/scope-tokens", status_code=201)
    def issue_scope_token(
        client_id: str, payload: IssueScopeTokenRequest, principal: ClientPrincipal
    ) -> ScopeTokenResponse:
        token = backoffice.issue_scope_token(
            principal,
            engagement_id=payload.engagement_id,
            purpose=payload.purpose,
            max_action=payload.max_action,
        )
        return ScopeTokenResponse(scope_token=token)

    return app


def _me(principal: Principal) -> MeResponse:
    ent = principal.entitlements
    return MeResponse(
        subject=principal.subject,
        scope=principal.scope,
        client_id=principal.client_id,
        is_platform_admin=principal.is_platform_admin,
        permissions=sorted(p.value for p in principal.permissions),
        plan_code=ent.plan_code,
        features=sorted(f.value for f in ent.features),
        quotas={q.value: v for q, v in ent.quotas.items()},
    )


def _role_json(role: Any) -> dict[str, Any]:
    return {
        "code": role.code,
        "name": role.name,
        "scope": role.scope.value,
        "description": role.description,
        "permissions": sorted(p.value for p in role.permissions),
    }
