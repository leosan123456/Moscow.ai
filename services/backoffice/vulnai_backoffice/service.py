"""`BackofficeService`: autenticação, gestão de acesso e ponte com o gate de escopo.

Divisão de responsabilidade que o resto do sistema depende:

* o **backoffice** decide *quem* pode pedir uma operação e *se o contrato comercial a
  cobre*;
* o **serviço de autorização** decide *se aquele alvo específico pode ser tocado*.

As duas checagens são independentes e ambas obrigatórias. Passar no RBAC não autoriza
tocar em nada; ter escopo contratado não dispensa permissão de usuário.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta

from vulnai_shared.audit import AuditLog
from vulnai_shared.clock import Clock, utcnow
from vulnai_shared.enums import ActionClass, AuditEventType
from vulnai_shared.models import Client
from vulnai_authorization import AuthorizationService
from vulnai_backoffice.credentials import (
    generate_api_key,
    hash_password,
    split_api_key,
    verify_api_secret,
    verify_password,
)
from vulnai_backoffice.entitlements import (
    NO_ENTITLEMENTS,
    PLAN_CATALOG,
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
    NotFoundError,
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
from vulnai_backoffice.permissions import Permission, PermissionScope, get_role
from vulnai_backoffice.rbac import Principal, resolve_principal
from vulnai_backoffice.repository import (
    ApiKeyRepository,
    ClientRepository,
    MembershipRepository,
    SessionRepository,
    SubscriptionRepository,
    UserRepository,
    InMemoryApiKeyRepository,
    InMemoryClientRepository,
    InMemoryMembershipRepository,
    InMemorySessionRepository,
    InMemorySubscriptionRepository,
    InMemoryUserRepository,
)

DEFAULT_SESSION_TTL = timedelta(hours=8)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class BackofficeService:
    """Fachada única do backoffice. Toda operação sensível emite `AuditEvent`."""

    def __init__(
        self,
        *,
        audit_log: AuditLog,
        users: UserRepository | None = None,
        memberships: MembershipRepository | None = None,
        clients: ClientRepository | None = None,
        subscriptions: SubscriptionRepository | None = None,
        api_keys: ApiKeyRepository | None = None,
        sessions: SessionRepository | None = None,
        authorization: AuthorizationService | None = None,
        plan_catalog: dict[str, Plan] | None = None,
        clock: Clock = utcnow,
    ) -> None:
        self._audit = audit_log
        self._users = users or InMemoryUserRepository()
        self._memberships = memberships or InMemoryMembershipRepository()
        self._clients = clients or InMemoryClientRepository()
        self._subscriptions = subscriptions or InMemorySubscriptionRepository()
        self._api_keys = api_keys or InMemoryApiKeyRepository()
        self._sessions = sessions or InMemorySessionRepository()
        self._authorization = authorization
        self._catalog = plan_catalog if plan_catalog is not None else PLAN_CATALOG
        self._clock = clock

    # ==================================================================== auth
    def login(self, email: str, password: str, *, ip_address: str | None = None) -> str:
        """Autentica por senha e devolve o token de sessão (em claro, uma única vez)."""
        now = self._clock()
        user = self._users.get_by_email(email)
        password_ok = verify_password(password, user.password_hash if user else None)

        if user is None or not password_ok or not user.status.can_authenticate:
            self._audit.record(
                AuditEventType.USER_LOGIN_FAILED,
                actor=email.strip().lower(),
                outcome="deny",
                details={"error_code": "authentication_failed", "via": "password"},
            )
            # Mensagem única para os três casos: senha errada, usuário inexistente e
            # conta suspensa. Diferenciar aqui vira enumeração de contas válidas.
            raise AuthenticationError("credenciais inválidas")

        token = secrets.token_urlsafe(32)
        session = Session(
            user_id=user.id,
            token_hash=_hash_token(token),
            issued_at=now,
            expires_at=now + DEFAULT_SESSION_TTL,
            ip_address=ip_address,
        )
        self._sessions.save(session)
        self._users.save(user.model_copy(update={"last_login_at": now}))
        self._audit.record(
            AuditEventType.USER_LOGIN,
            actor=user.email,
            outcome="allow",
            details={"event": "login", "session_id": session.id, "via": "password"},
        )
        return token

    def principal_from_session(self, token: str, *, client_id: str | None = None) -> Principal:
        """Resolve o principal de uma sessão, no tenant escolhido no seletor de contexto."""
        now = self._clock()
        session = self._sessions.get_by_token_hash(_hash_token(token))
        if session is None or not session.is_valid(now):
            raise AuthenticationError("sessão inválida ou expirada")

        user = self._users.get(session.user_id)
        if user is None or not user.status.can_authenticate:
            raise AuthenticationError("usuário sem acesso")

        return self._build_principal(user, client_id, via="session", now=now)

    def principal_from_api_key(self, raw_key: str) -> Principal:
        """Resolve o principal de uma chave de API, herdando o vínculo que a criou."""
        now = self._clock()
        parts = split_api_key(raw_key)
        if parts is None:
            raise AuthenticationError("chave de API inválida")

        key_id, secret = parts
        api_key = self._api_keys.get_by_key_id(key_id)
        if (
            api_key is None
            or not api_key.is_usable(now)
            or not verify_api_secret(secret, api_key.secret_hash)
        ):
            raise AuthenticationError("chave de API inválida")

        membership = self._memberships.get(api_key.membership_id)
        if membership is None or not membership.is_active(now):
            # Revogar o vínculo revoga toda chave emitida sob ele, sem passo extra.
            raise AuthenticationError("vínculo associado à chave não está mais ativo")

        user = self._users.get(membership.user_id)
        if user is None:
            raise AuthenticationError("usuário associado à chave não existe")

        self._api_keys.save(api_key.model_copy(update={"last_used_at": now}))
        return self._build_principal(
            user, api_key.client_id, via="api_key", now=now, subject=f"apikey:{api_key.name}"
        )

    def logout(self, token: str) -> None:
        session = self._sessions.get_by_token_hash(_hash_token(token))
        if session is not None:
            self._sessions.save(session.model_copy(update={"revoked": True}))

    def _build_principal(
        self,
        user: User,
        client_id: str | None,
        *,
        via: str,
        now: datetime,
        subject: str | None = None,
    ) -> Principal:
        entitlements = (
            self.entitlements_for(client_id) if client_id is not None else NO_ENTITLEMENTS
        )
        return resolve_principal(
            subject=subject or user.email,
            user_id=user.id,
            memberships=self._memberships.list_for_user(user.id),
            moment=now,
            client_id=client_id,
            entitlements=entitlements,
            via=via,
        )

    # ============================================================== plataforma
    def create_client(self, actor: Principal, *, name: str, security_contact: str) -> Client:
        actor.require(Permission.PLATFORM_CLIENT_MANAGE)
        client = Client(name=name, security_contact=security_contact)
        self._clients.save(client)
        self._audit.record(
            AuditEventType.CLIENT_CREATED,
            actor=actor.subject,
            outcome="created",
            client_id=client.id,
            details={"event": "client.created", "name": name},
        )
        return client

    def set_subscription(
        self,
        actor: Principal,
        *,
        client_id: str,
        plan_code: str,
        status: SubscriptionStatus = SubscriptionStatus.ACTIVE,
        starts_at: datetime | None = None,
        ends_at: datetime | None = None,
        extra_features: frozenset[Feature] = frozenset(),
        excluded_features: frozenset[Feature] = frozenset(),
        quota_overrides: dict[Quota, int] | None = None,
    ) -> Subscription:
        """Contrata ou altera o plano de um tenant (operação comercial)."""
        actor.require(Permission.PLATFORM_SUBSCRIPTION_MANAGE)
        if plan_code not in self._catalog:
            raise NotFoundError(f"plano {plan_code!r} não existe no catálogo")
        if self._clients.get(client_id) is None:
            raise NotFoundError(f"cliente {client_id!r} não existe")

        previous = self._subscriptions.get_for_client(client_id)
        subscription = Subscription(
            client_id=client_id,
            plan_code=plan_code,
            status=status,
            starts_at=starts_at or self._clock(),
            ends_at=ends_at,
            extra_features=extra_features,
            excluded_features=excluded_features,
            quota_overrides=quota_overrides or {},
        )
        self._subscriptions.save(subscription)
        self._audit.record(
            AuditEventType.SUBSCRIPTION_CHANGED,
            actor=actor.subject,
            outcome="updated",
            client_id=client_id,
            details={
                "event": "subscription.changed",
                "from_plan": previous.plan_code if previous else None,
                "to_plan": plan_code,
                "status": status.value,
                "extra_features": sorted(f.value for f in extra_features),
                "excluded_features": sorted(f.value for f in excluded_features),
            },
        )
        return subscription

    def entitlements_for(self, client_id: str) -> Entitlements:
        """Resolução comercial vigente de um tenant."""
        subscription = self._subscriptions.get_for_client(client_id)
        return resolve_entitlements(subscription, self._clock(), catalog=self._catalog)

    # ================================================================= usuários
    def create_user(
        self,
        actor: Principal,
        *,
        email: str,
        full_name: str,
        password: str | None = None,
    ) -> User:
        """Cria usuário global. Vincular a um tenant é passo separado (`grant_membership`)."""
        actor.require(Permission.PLATFORM_USER_MANAGE)
        if self._users.get_by_email(email) is not None:
            raise UserAlreadyExistsError(f"já existe usuário com o e-mail {email!r}")

        user = User(
            email=email,
            full_name=full_name,
            status=UserStatus.ACTIVE if password else UserStatus.INVITED,
            password_hash=hash_password(password) if password else None,
        )
        self._users.save(user)
        self._audit.record(
            AuditEventType.USER_CREATED,
            actor=actor.subject,
            outcome="created",
            details={"event": "user.created", "user_id": user.id, "email": user.email},
        )
        return user

    def invite_client_user(
        self,
        actor: Principal,
        *,
        client_id: str,
        email: str,
        full_name: str,
        role_codes: tuple[str, ...],
    ) -> tuple[User, Membership]:
        """Convida uma pessoa do cliente e já a vincula com papéis do tenant.

        Respeita a cota `MAX_USERS` do plano — este é o ponto onde a regra comercial
        encosta na gestão de acesso.
        """
        actor.require_client(client_id)
        actor.require(Permission.CLIENT_USER_MANAGE)
        actor.require_quota(Quota.MAX_USERS, self._count_client_users(client_id))

        user = self._users.get_by_email(email)
        if user is None:
            user = self._users.save(User(email=email, full_name=full_name))

        membership = self._save_membership(
            Membership(
                user_id=user.id,
                scope=PermissionScope.CLIENT,
                client_id=client_id,
                role_codes=role_codes,
                granted_by=actor.subject,
            ),
            actor=actor,
            event="membership.granted",
        )
        return user, membership

    def grant_membership(
        self,
        actor: Principal,
        *,
        user_id: str,
        scope: PermissionScope,
        client_id: str | None = None,
        role_codes: tuple[str, ...] = (),
        extra_permissions: frozenset[Permission] = frozenset(),
        denied_permissions: frozenset[Permission] = frozenset(),
        expires_at: datetime | None = None,
    ) -> Membership:
        """Concede vínculo. Vínculo de plataforma só sai da mão de quem administra a plataforma."""
        if scope is PermissionScope.PLATFORM:
            actor.require(Permission.PLATFORM_ROLE_MANAGE)
        else:
            if client_id is None:
                raise NotFoundError("vínculo de cliente exige client_id")
            actor.require_client(client_id)
            actor.require(Permission.CLIENT_USER_MANAGE)
            self._require_grantable(actor, role_codes, extra_permissions)

        if self._users.get(user_id) is None:
            raise NotFoundError(f"usuário {user_id!r} não existe")

        return self._save_membership(
            Membership(
                user_id=user_id,
                scope=scope,
                client_id=client_id,
                role_codes=role_codes,
                extra_permissions=extra_permissions,
                denied_permissions=denied_permissions,
                expires_at=expires_at,
                granted_by=actor.subject,
            ),
            actor=actor,
            event="membership.granted",
        )

    def revoke_membership(self, actor: Principal, *, membership_id: str) -> Membership:
        membership = self._memberships.get(membership_id)
        if membership is None:
            raise NotFoundError(f"vínculo {membership_id!r} não existe")

        if membership.scope is PermissionScope.PLATFORM:
            actor.require(Permission.PLATFORM_ROLE_MANAGE)
        else:
            actor.require_client(membership.client_id or "")
            actor.require(Permission.CLIENT_USER_MANAGE)

        revoked = self._memberships.save(
            membership.model_copy(update={"status": MembershipStatus.REVOKED})
        )
        self._audit.record(
            AuditEventType.MEMBERSHIP_REVOKED,
            actor=actor.subject,
            outcome="revoked",
            client_id=membership.client_id,
            details={"event": "membership.revoked", "membership_id": membership_id},
        )
        return revoked

    def _require_grantable(
        self,
        actor: Principal,
        role_codes: tuple[str, ...],
        extra_permissions: frozenset[Permission],
    ) -> None:
        """Ninguém concede o que não tem.

        Sem esta checagem, um `client_analyst` com `client:user.manage` conseguiria criar
        um `client_owner` e escalar privilégio pelo caminho mais óbvio possível.
        """
        requested: set[Permission] = set(extra_permissions)
        for code in role_codes:
            requested |= get_role(code).permissions

        missing = sorted(p.value for p in requested - actor.permissions)
        if missing:
            from vulnai_backoffice.errors import PermissionDeniedError

            raise PermissionDeniedError(
                f"{actor.subject} não pode conceder permissões que não possui: {missing}"
            )

    def _save_membership(self, membership: Membership, *, actor: Principal, event: str) -> Membership:
        saved = self._memberships.save(membership)
        self._audit.record(
            AuditEventType.MEMBERSHIP_GRANTED,
            actor=actor.subject,
            outcome="granted",
            client_id=membership.client_id,
            details={
                "event": event,
                "membership_id": saved.id,
                "user_id": saved.user_id,
                "scope": saved.scope.value,
                "roles": list(saved.role_codes),
                "extra_permissions": sorted(p.value for p in saved.extra_permissions),
                "denied_permissions": sorted(p.value for p in saved.denied_permissions),
            },
        )
        return saved

    def _count_client_users(self, client_id: str) -> int:
        return len(
            {
                m.user_id
                for m in self._memberships.list_for_client(client_id)
                if m.status is MembershipStatus.ACTIVE
            }
        )

    # ============================================================ chaves de API
    def create_api_key(
        self,
        actor: Principal,
        *,
        name: str,
        expires_at: datetime | None = None,
    ) -> tuple[str, ApiKey]:
        """Emite chave de API para o vínculo do próprio ator. Retorna a chave em claro."""
        actor.require(Permission.CLIENT_APIKEY_MANAGE)
        actor.require_feature(Feature.API_ACCESS)
        if not actor.membership_ids:
            raise NotFoundError("principal sem vínculo ao qual atrelar a chave")

        raw, key_id, secret_hash = generate_api_key()
        api_key = self._api_keys.save(
            ApiKey(
                membership_id=actor.membership_ids[0],
                client_id=actor.client_id,
                name=name,
                key_id=key_id,
                secret_hash=secret_hash,
                created_by=actor.subject,
                expires_at=expires_at,
            )
        )
        self._audit.record(
            AuditEventType.APIKEY_CREATED,
            actor=actor.subject,
            outcome="issued",
            client_id=actor.client_id,
            details={"event": "apikey.created", "key_id": key_id, "name": name},
        )
        return raw, api_key

    def revoke_api_key(self, actor: Principal, *, key_id: str) -> ApiKey:
        actor.require(Permission.CLIENT_APIKEY_MANAGE)
        api_key = self._api_keys.get_by_key_id(key_id)
        if api_key is None or api_key.client_id != actor.client_id:
            raise NotFoundError(f"chave {key_id!r} não encontrada neste cliente")

        revoked = self._api_keys.save(api_key.model_copy(update={"revoked": True}))
        self._audit.record(
            AuditEventType.APIKEY_REVOKED,
            actor=actor.subject,
            outcome="revoked",
            client_id=actor.client_id,
            details={"event": "apikey.revoked", "key_id": key_id},
        )
        return revoked

    # =================================================== ponte com o gate de escopo
    def issue_scope_token(
        self,
        actor: Principal,
        *,
        engagement_id: str,
        purpose: str,
        max_action: ActionClass = ActionClass.PASSIVE,
    ) -> str:
        """Emite `authorized_scope_token` — só depois de RBAC + contrato comercial.

        As três barreiras, em ordem: permissão do usuário, funcionalidade contratada e,
        por último, o gate de escopo, que é quem de fato decide o que pode ser tocado.
        """
        if self._authorization is None:
            raise NotFoundError("serviço de autorização não configurado")

        actor.require(Permission.SCOPE_TOKEN_ISSUE)
        if max_action is ActionClass.INTRUSIVE:
            actor.require(Permission.SCAN_RUN_INTRUSIVE)
            actor.require_feature(Feature.INTRUSIVE_CHECKS)
        elif max_action is ActionClass.ACTIVE_NON_INTRUSIVE:
            actor.require(Permission.SCAN_RUN)

        return self._authorization.issue_scope_token(
            engagement_id,
            operator=actor.subject,
            purpose=purpose,
            max_action=max_action,
            # Amarra a emissão ao tenant do principal: sem isso, conhecer o id de uma
            # engagement de outro cliente seria suficiente para obter token dela.
            expected_client_id=actor.client_id,
        )
