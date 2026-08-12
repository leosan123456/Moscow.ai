"""Erros do backoffice."""

from __future__ import annotations

from vulnai_shared.errors import VulnAIError


class BackofficeError(VulnAIError):
    """Base dos erros do backoffice."""


class AuthenticationError(BackofficeError):
    """Credencial inválida, expirada ou conta impedida de autenticar.

    Mensagem propositalmente genérica no caminho de login: distinguir "usuário não existe"
    de "senha errada" entrega uma lista de e-mails válidos a quem estiver testando.
    """


class PermissionDeniedError(BackofficeError):
    """Principal autenticado, mas sem a permissão exigida."""

    def __init__(self, message: str, *, permission: str | None = None) -> None:
        super().__init__(message)
        self.permission = permission


class TenantAccessError(PermissionDeniedError):
    """Tentativa de agir sobre um tenant ao qual o principal não está vinculado."""


class EntitlementError(BackofficeError):
    """Bloqueio comercial: o contrato do cliente não cobre a operação."""


class FeatureNotContractedError(EntitlementError):
    """Funcionalidade não incluída no plano vigente."""

    def __init__(self, message: str, *, feature: str | None = None) -> None:
        super().__init__(message)
        self.feature = feature


class QuotaExceededError(EntitlementError):
    """Limite do plano atingido."""

    def __init__(self, message: str, *, quota: str | None = None, limit: int | None = None) -> None:
        super().__init__(message)
        self.quota = quota
        self.limit = limit


class SubscriptionInactiveError(EntitlementError):
    """Nenhuma assinatura vigente para o tenant."""


class UserAlreadyExistsError(BackofficeError):
    """E-mail já cadastrado."""


class NotFoundError(BackofficeError):
    """Recurso inexistente dentro do escopo consultado."""
