"""Enumerações do domínio."""

from __future__ import annotations

from enum import StrEnum


class ActionClass(StrEnum):
    """Classe de intensidade de uma ação sobre um ativo do cliente.

    A ordem importa: `PASSIVE < ACTIVE_NON_INTRUSIVE < INTRUSIVE`. Um token concede uma
    classe máxima, e qualquer ação acima dela é negada.
    """

    #: Não toca o ativo. Consulta de OSINT, CVE/NVD, SBOM, inventário via API do cloud.
    PASSIVE = "passive"
    #: Toca o ativo, sem alterar estado: TCP connect, banner, header HTTP, versão TLS.
    ACTIVE_NON_INTRUSIVE = "active_non_intrusive"
    #: Pode alterar estado ou degradar o serviço. Exige opt-in explícito + aprovação humana.
    INTRUSIVE = "intrusive"

    @property
    def level(self) -> int:
        return _ACTION_LEVELS[self]

    def dominates(self, other: ActionClass) -> bool:
        """Verdadeiro se esta classe permite tudo que `other` exige."""
        return self.level >= other.level


_ACTION_LEVELS: dict[ActionClass, int] = {
    ActionClass.PASSIVE: 0,
    ActionClass.ACTIVE_NON_INTRUSIVE: 1,
    ActionClass.INTRUSIVE: 2,
}


class TargetKind(StrEnum):
    """Natureza de um alvo já normalizado."""

    IP = "ip"
    HOSTNAME = "hostname"
    URL = "url"
    CLOUD_ACCOUNT = "cloud_account"
    CLOUD_RESOURCE = "cloud_resource"


class ScopeRuleKind(StrEnum):
    """Tipo de regra de escopo declarada no contrato."""

    CIDR = "cidr"
    IP = "ip"
    #: Casa o apex e todos os subdomínios (`example.com` -> `api.example.com`).
    DOMAIN = "domain"
    #: Casa apenas o host exato.
    HOSTNAME = "hostname"
    #: Casa URLs cujo host e prefixo de path batem.
    URL_PREFIX = "url_prefix"
    CLOUD_ACCOUNT = "cloud_account"


class ScopeRuleEffect(StrEnum):
    """Efeito de uma regra. Exclusão sempre vence inclusão."""

    INCLUDE = "include"
    EXCLUDE = "exclude"


class EngagementStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class Severity(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    """Confiança do achado — alimenta a redução de falso positivo do núcleo de IA."""

    TENTATIVE = "tentative"
    FIRM = "firm"
    CONFIRMED = "confirmed"


class FindingStatus(StrEnum):
    NEW = "new"
    TRIAGED = "triaged"
    AWAITING_HUMAN_REVIEW = "awaiting_human_review"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    REMEDIATED = "remediated"


class AssetCriticality(StrEnum):
    """Criticidade de negócio do ativo — entra no motor de priorização (M4)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    MISSION_CRITICAL = "mission_critical"


class AuditEventType(StrEnum):
    # Backoffice: identidade e acesso
    USER_LOGIN = "user.login"
    USER_LOGIN_FAILED = "user.login_failed"
    USER_CREATED = "user.created"
    MEMBERSHIP_GRANTED = "membership.granted"
    MEMBERSHIP_REVOKED = "membership.revoked"
    APIKEY_CREATED = "apikey.created"
    APIKEY_REVOKED = "apikey.revoked"

    # Backoffice: comercial
    CLIENT_CREATED = "client.created"
    SUBSCRIPTION_CHANGED = "subscription.changed"

    # Pipeline operacional
    ENGAGEMENT_CREATED = "engagement.created"
    ENGAGEMENT_STATUS_CHANGED = "engagement.status_changed"
    SCOPE_UPDATED = "scope.updated"
    TOKEN_ISSUED = "token.issued"
    TOKEN_REVOKED = "token.revoked"
    AUTHORIZATION_ALLOWED = "authorization.allowed"
    AUTHORIZATION_DENIED = "authorization.denied"
    HUMAN_APPROVAL_GRANTED = "approval.granted"
    ASSET_TOUCHED = "asset.touched"
    FINDING_CREATED = "finding.created"
    FINDING_STATUS_CHANGED = "finding.status_changed"
    REPORT_GENERATED = "report.generated"
