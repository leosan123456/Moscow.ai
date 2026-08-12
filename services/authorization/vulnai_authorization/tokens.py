"""`authorized_scope_token`: prova portável de que uma execução foi autorizada.

Formato: `vast1.<payload-base64url>.<hmac-sha256-base64url>`.

O token **não** é a fonte da verdade do escopo — ele carrega apenas o *digest* do escopo
vigente na emissão. A checagem de alvo sempre reavalia contra o escopo armazenado, e o
digest serve para invalidar tokens emitidos sob um contrato que já mudou.

Escolha de HMAC em vez de assinatura assimétrica: emissor e verificador são o mesmo
serviço interno. Se um dia o token precisar ser verificado por terceiros, o campo de
versão (`vast1`) permite introduzir Ed25519 sem quebrar tokens existentes.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from vulnai_shared.canonical import b64decode, b64encode, canonical_bytes
from vulnai_shared.clock import Clock, ensure_utc, utcnow
from vulnai_shared.enums import ActionClass
from vulnai_shared.errors import (
    ConfigurationError,
    ScopeTokenError,
    TokenExpiredError,
    TokenSignatureError,
)

TOKEN_PREFIX = "vast1"
DEFAULT_TTL = timedelta(hours=8)
MIN_SECRET_BYTES = 32


@dataclass(frozen=True, slots=True)
class ScopeToken:
    """Conteúdo verificado de um token de escopo."""

    #: JWT-style token id, usado para revogação e correlação na auditoria.
    jti: str
    client_id: str
    engagement_id: str
    scope_digest: str
    scope_version: int
    operator: str
    #: Teto de intensidade concedido a este token especificamente.
    max_action: ActionClass
    issued_at: datetime
    expires_at: datetime
    purpose: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "jti": self.jti,
            "cid": self.client_id,
            "eid": self.engagement_id,
            "sd": self.scope_digest,
            "sv": self.scope_version,
            "op": self.operator,
            "act": self.max_action.value,
            "iat": int(self.issued_at.timestamp()),
            "exp": int(self.expires_at.timestamp()),
            "pur": self.purpose,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> ScopeToken:
        from datetime import UTC

        try:
            return cls(
                jti=str(payload["jti"]),
                client_id=str(payload["cid"]),
                engagement_id=str(payload["eid"]),
                scope_digest=str(payload["sd"]),
                scope_version=int(payload["sv"]),
                operator=str(payload["op"]),
                max_action=ActionClass(payload["act"]),
                issued_at=datetime.fromtimestamp(int(payload["iat"]), tz=UTC),
                expires_at=datetime.fromtimestamp(int(payload["exp"]), tz=UTC),
                purpose=str(payload["pur"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ScopeTokenError(f"payload de token inválido: {exc}") from exc


class ScopeTokenSigner:
    """Emite e verifica tokens de escopo."""

    def __init__(self, secret: bytes, *, clock: Clock = utcnow) -> None:
        if len(secret) < MIN_SECRET_BYTES:
            raise ConfigurationError(
                f"segredo de assinatura precisa de ao menos {MIN_SECRET_BYTES} bytes"
            )
        self._secret = secret
        self._clock = clock
        self._revoked: set[str] = set()

    # ---------------------------------------------------------------- emissão
    def issue(
        self,
        *,
        client_id: str,
        engagement_id: str,
        scope_digest: str,
        scope_version: int,
        operator: str,
        max_action: ActionClass,
        purpose: str,
        ttl: timedelta = DEFAULT_TTL,
        not_after: datetime | None = None,
    ) -> tuple[str, ScopeToken]:
        """Emite um token. Retorna `(token_serializado, conteúdo)`.

        `not_after` limita o vencimento ao fim da janela contratada: um token nunca
        sobrevive à autorização que o originou, mesmo com TTL maior.
        """
        if ttl <= timedelta(0):
            raise ConfigurationError("ttl do token precisa ser positivo")

        issued_at = self._clock()
        expires_at = issued_at + ttl
        if not_after is not None:
            expires_at = min(expires_at, ensure_utc(not_after))
        if expires_at <= issued_at:
            raise ConfigurationError(
                "janela de autorização já encerrada; não há TTL válido a emitir"
            )

        token = ScopeToken(
            jti=secrets.token_urlsafe(16),
            client_id=client_id,
            engagement_id=engagement_id,
            scope_digest=scope_digest,
            scope_version=scope_version,
            operator=operator,
            max_action=max_action,
            issued_at=issued_at,
            expires_at=expires_at,
            purpose=purpose,
        )
        return self.serialize(token), token

    def serialize(self, token: ScopeToken) -> str:
        payload = b64encode(canonical_bytes(token.to_payload()))
        return f"{TOKEN_PREFIX}.{payload}.{self._sign(payload)}"

    # ------------------------------------------------------------ verificação
    def verify(self, raw: str) -> ScopeToken:
        """Verifica assinatura, expiração e revogação. Levanta em qualquer falha."""
        if not isinstance(raw, str) or not raw:
            raise ScopeTokenError("token de escopo ausente")

        parts = raw.split(".")
        if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
            raise ScopeTokenError("formato de token de escopo inválido")

        _, payload_b64, signature = parts
        if not hmac.compare_digest(self._sign(payload_b64), signature):
            raise TokenSignatureError("assinatura do token de escopo inválida")

        try:
            import json

            payload = json.loads(b64decode(payload_b64))
        except Exception as exc:  # noqa: BLE001 - qualquer falha aqui é token inválido
            raise ScopeTokenError("payload do token de escopo ilegível") from exc

        token = ScopeToken.from_payload(payload)

        if token.jti in self._revoked:
            raise ScopeTokenError(f"token {token.jti} revogado")
        if self._clock() >= token.expires_at:
            raise TokenExpiredError(
                f"token expirado em {token.expires_at.isoformat()}"
            )
        return token

    # -------------------------------------------------------------- revogação
    def revoke(self, jti: str) -> None:
        """Revoga um token — parada de emergência a pedido do cliente."""
        self._revoked.add(jti)

    def is_revoked(self, jti: str) -> bool:
        return jti in self._revoked

    def _sign(self, payload_b64: str) -> str:
        digest = hmac.new(self._secret, payload_b64.encode("ascii"), "sha256").digest()
        return b64encode(digest)


def generate_secret() -> bytes:
    """Segredo novo para o assinador (bootstrap / rotação)."""
    return secrets.token_bytes(MIN_SECRET_BYTES)
