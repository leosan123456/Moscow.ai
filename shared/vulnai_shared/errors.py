"""Hierarquia de erros da plataforma.

Decisões de autorização **nunca** retornam um booleano silencioso: o caminho de negação
levanta exceção para que um `if` esquecido não vire uma varredura fora de escopo.
"""

from __future__ import annotations


class VulnAIError(Exception):
    """Erro base da plataforma."""


class ConfigurationError(VulnAIError):
    """Configuração inválida ou ausente (chave de assinatura, política, repositório)."""


# --------------------------------------------------------------------------------------
# Autorização
# --------------------------------------------------------------------------------------


class AuthorizationError(VulnAIError):
    """Base de toda negação do gate de autorização."""


class InvalidTargetError(AuthorizationError):
    """Alvo malformado, ambíguo ou impossível de normalizar com segurança."""


class OutOfScopeError(AuthorizationError):
    """Alvo não pertence ao escopo contratado (ou casa com uma regra de exclusão)."""


class ScopeTokenError(AuthorizationError):
    """Token de escopo ausente, malformado ou inválido."""


class TokenSignatureError(ScopeTokenError):
    """Assinatura HMAC inválida — token forjado ou adulterado."""


class TokenExpiredError(ScopeTokenError):
    """Token expirado."""


class ScopeDriftError(ScopeTokenError):
    """O escopo mudou desde a emissão do token (digest divergente)."""


class EngagementWindowError(AuthorizationError):
    """Execução fora da janela de autorização contratada."""


class EngagementStateError(AuthorizationError):
    """Engajamento suspenso, encerrado ou ainda não ativo."""


class TenantMismatchError(AuthorizationError):
    """Tentativa de acesso cruzado entre tenants."""


class ActionNotAuthorizedError(AuthorizationError):
    """Classe de ação não concedida ao token/engajamento."""


class IntrusiveActionNotAuthorizedError(ActionNotAuthorizedError):
    """Ação intrusiva sem opt-in explícito registrado."""


class HumanApprovalRequiredError(AuthorizationError):
    """Ação exige aprovação humana registrada que não foi encontrada."""


class RateLimitExceededError(AuthorizationError):
    """Limite de intensidade por alvo/engajamento excedido."""


class SafetyPolicyError(AuthorizationError):
    """Alvo bloqueado por política de segurança independente do escopo."""


# --------------------------------------------------------------------------------------
# Auditoria
# --------------------------------------------------------------------------------------


class AuditError(VulnAIError):
    """Base dos erros da trilha de auditoria."""


class AuditChainError(AuditError):
    """Cadeia de auditoria quebrada: hash, sequência ou encadeamento inconsistente."""
