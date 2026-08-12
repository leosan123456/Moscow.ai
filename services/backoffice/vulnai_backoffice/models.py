"""Entidades de identidade e acesso do backoffice."""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnai_shared.clock import ensure_utc
from vulnai_shared.models import Entity, Identifier, new_id
from vulnai_backoffice.permissions import Permission, PermissionScope, get_role

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+(\.[^@\s.]+)+$")


class UserStatus(StrEnum):
    INVITED = "invited"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DISABLED = "disabled"

    @property
    def can_authenticate(self) -> bool:
        return self is UserStatus.ACTIVE


class MembershipStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class User(Entity):
    """Pessoa com acesso ao backoffice.

    O usuário é global; o que o vincula a um tenant é o `Membership`. Um consultor pode
    atender vários clientes sem duplicar conta — e revogar o acesso de um cliente não
    afeta os outros.
    """

    email: str = Field(min_length=3, max_length=320)
    full_name: str = Field(min_length=1, max_length=256)
    status: UserStatus = UserStatus.INVITED
    password_hash: str | None = None
    mfa_enabled: bool = False
    last_login_at: datetime | None = None

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, value: str) -> str:
        email = value.strip().lower()
        if not _EMAIL_RE.match(email):
            raise ValueError(f"e-mail inválido: {value!r}")
        return email


class Membership(Entity):
    """Vínculo de um usuário a um escopo (plataforma ou um tenant específico).

    Concessões pontuais (`extra_permissions`) e negações (`denied_permissions`) existem
    para exceção contratual sem inventar papel novo. Negação vence sempre — inclusive
    sobre `client_owner`.
    """

    user_id: Identifier
    scope: PermissionScope
    #: Obrigatório em escopo CLIENT, proibido em escopo PLATFORM.
    client_id: Identifier | None = None
    role_codes: tuple[str, ...] = ()
    extra_permissions: frozenset[Permission] = frozenset()
    denied_permissions: frozenset[Permission] = frozenset()
    status: MembershipStatus = MembershipStatus.ACTIVE
    expires_at: datetime | None = None
    granted_by: str | None = None

    @field_validator("expires_at")
    @classmethod
    def _utc(cls, value: datetime | None) -> datetime | None:
        return None if value is None else ensure_utc(value)

    @model_validator(mode="after")
    def _validate_scope(self) -> Membership:
        if self.scope is PermissionScope.PLATFORM and self.client_id is not None:
            raise ValueError("vínculo de plataforma não pode ter client_id")
        if self.scope is PermissionScope.CLIENT and not self.client_id:
            raise ValueError("vínculo de cliente exige client_id")

        for code in self.role_codes:
            role = get_role(code)
            if role.scope is not self.scope:
                raise ValueError(
                    f"papel {code!r} é de escopo {role.scope.value}, "
                    f"incompatível com o vínculo {self.scope.value}"
                )

        # Concessão pontual não pode contrabandear permissão de plataforma para um tenant.
        invalid = [p for p in self.extra_permissions if p.scope is not self.scope]
        if invalid:
            raise ValueError(
                "extra_permissions fora do escopo do vínculo: "
                f"{sorted(p.value for p in invalid)}"
            )
        return self

    def is_active(self, moment: datetime) -> bool:
        if self.status is not MembershipStatus.ACTIVE:
            return False
        return self.expires_at is None or ensure_utc(moment) < self.expires_at


class ApiKey(Entity):
    """Credencial de máquina, sempre atrelada a um `Membership`.

    Não existe chave "solta": ela herda exatamente as permissões do vínculo, então
    revogar o vínculo revoga a chave junto.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    membership_id: Identifier
    client_id: Identifier | None = None
    name: str = Field(min_length=1, max_length=128)
    key_id: str = Field(min_length=8, max_length=64)
    secret_hash: str = Field(min_length=32, max_length=128)
    created_by: str | None = None
    expires_at: datetime | None = None
    revoked: bool = False
    last_used_at: datetime | None = None

    @field_validator("expires_at", "last_used_at")
    @classmethod
    def _utc(cls, value: datetime | None) -> datetime | None:
        return None if value is None else ensure_utc(value)

    def is_usable(self, moment: datetime) -> bool:
        if self.revoked:
            return False
        return self.expires_at is None or ensure_utc(moment) < self.expires_at


class Session(BaseModel):
    """Sessão de navegador emitida após login."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: Identifier = Field(default_factory=new_id)
    user_id: Identifier
    token_hash: str
    issued_at: datetime
    expires_at: datetime
    #: Tenant selecionado na sessão. `None` = console de plataforma.
    active_client_id: Identifier | None = None
    ip_address: str | None = None
    user_agent: str | None = Field(default=None, max_length=512)
    revoked: bool = False

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    def is_valid(self, moment: datetime) -> bool:
        return not self.revoked and ensure_utc(moment) < self.expires_at
