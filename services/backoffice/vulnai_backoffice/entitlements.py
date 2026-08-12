"""Camada comercial: planos, funcionalidades contratadas e cotas.

A regra central do backoffice é a interseção de duas coisas independentes:

    permissão efetiva = o que o **papel** concede  ∩  o que o **plano** habilita

Um `client_owner` tem `scan:run_intrusive` no papel, mas se o plano contratado não inclui
`INTRUSIVE_CHECKS` a permissão simplesmente não existe para aquele tenant. Isso mantém a
regra comercial fora do código de produto: mudar de plano muda o que a interface mostra,
sem `if plano == "enterprise"` espalhado.

Importante: entitlement é **comercial**, não é autorização de segurança. Ter o plano
certo não autoriza tocar em nada — o gate de escopo continua sendo a última palavra.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vulnai_shared.clock import ensure_utc
from vulnai_shared.models import Identifier, new_id
from vulnai_backoffice.permissions import Permission


class Feature(StrEnum):
    """Funcionalidade comercializável."""

    ASSET_DISCOVERY = "asset_discovery"
    CONTINUOUS_MONITORING = "continuous_monitoring"
    CLOUD_POSTURE = "cloud_posture"
    AI_SEVERITY_SCORING = "ai_severity_scoring"
    LLM_RAG_ANALYST = "llm_rag_analyst"
    INTRUSIVE_CHECKS = "intrusive_checks"
    TICKETING_INTEGRATION = "ticketing_integration"
    API_ACCESS = "api_access"
    SSO = "sso"
    CUSTOM_REPORTS = "custom_reports"
    MULTI_ENGAGEMENT = "multi_engagement"


class Quota(StrEnum):
    """Limite numérico do plano. `-1` significa ilimitado."""

    MAX_ENGAGEMENTS = "max_engagements"
    MAX_ASSETS = "max_assets"
    MAX_SCANS_PER_MONTH = "max_scans_per_month"
    MAX_USERS = "max_users"
    MAX_CONCURRENT_TARGETS = "max_concurrent_targets"
    DATA_RETENTION_DAYS = "data_retention_days"


UNLIMITED = -1


#: Permissões que só existem se a funcionalidade correspondente estiver contratada.
FEATURE_GATED_PERMISSIONS: dict[Permission, Feature] = {
    Permission.SCAN_RUN_INTRUSIVE: Feature.INTRUSIVE_CHECKS,
    Permission.AI_INSIGHTS_READ: Feature.AI_SEVERITY_SCORING,
    Permission.REPORT_EXPORT: Feature.CUSTOM_REPORTS,
    Permission.CLIENT_APIKEY_MANAGE: Feature.API_ACCESS,
}


class SubscriptionStatus(StrEnum):
    TRIAL = "trial"
    ACTIVE = "active"
    PAST_DUE = "past_due"
    SUSPENDED = "suspended"
    CANCELLED = "cancelled"

    @property
    def grants_access(self) -> bool:
        """`PAST_DUE` mantém acesso: cortar visibilidade de vulnerabilidade por
        inadimplência deixaria o cliente cego para risco que já existe. A cobrança é
        tratada comercialmente; a suspensão é uma decisão explícita."""
        return self in (SubscriptionStatus.TRIAL, SubscriptionStatus.ACTIVE,
                        SubscriptionStatus.PAST_DUE)


@dataclass(frozen=True, slots=True)
class Plan:
    """Plano comercial ofertado."""

    code: str
    name: str
    features: frozenset[Feature]
    quotas: dict[Quota, int]
    description: str = ""

    def quota(self, quota: Quota) -> int:
        return self.quotas.get(quota, 0)


ESSENTIAL = Plan(
    code="essential",
    name="Essencial",
    features=frozenset({Feature.ASSET_DISCOVERY, Feature.AI_SEVERITY_SCORING}),
    quotas={
        Quota.MAX_ENGAGEMENTS: 1,
        Quota.MAX_ASSETS: 250,
        Quota.MAX_SCANS_PER_MONTH: 4,
        Quota.MAX_USERS: 5,
        Quota.MAX_CONCURRENT_TARGETS: 8,
        Quota.DATA_RETENTION_DAYS: 90,
    },
    description="Descoberta e priorização por IA para um único engajamento.",
)

PROFESSIONAL = Plan(
    code="professional",
    name="Profissional",
    features=frozenset(
        {
            Feature.ASSET_DISCOVERY,
            Feature.CONTINUOUS_MONITORING,
            Feature.CLOUD_POSTURE,
            Feature.AI_SEVERITY_SCORING,
            Feature.LLM_RAG_ANALYST,
            Feature.TICKETING_INTEGRATION,
            Feature.API_ACCESS,
            Feature.CUSTOM_REPORTS,
            Feature.MULTI_ENGAGEMENT,
        }
    ),
    quotas={
        Quota.MAX_ENGAGEMENTS: 10,
        Quota.MAX_ASSETS: 5_000,
        Quota.MAX_SCANS_PER_MONTH: 60,
        Quota.MAX_USERS: 40,
        Quota.MAX_CONCURRENT_TARGETS: 32,
        Quota.DATA_RETENTION_DAYS: 365,
    },
    description="Monitoramento contínuo, LLM/RAG e integração com ticketing.",
)

ENTERPRISE = Plan(
    code="enterprise",
    name="Enterprise",
    features=frozenset(Feature),
    quotas={
        Quota.MAX_ENGAGEMENTS: UNLIMITED,
        Quota.MAX_ASSETS: UNLIMITED,
        Quota.MAX_SCANS_PER_MONTH: UNLIMITED,
        Quota.MAX_USERS: UNLIMITED,
        Quota.MAX_CONCURRENT_TARGETS: 128,
        Quota.DATA_RETENTION_DAYS: 1095,
    },
    description="Catálogo completo, incluindo verificação intrusiva sob contrato e SSO.",
)

PLAN_CATALOG: dict[str, Plan] = {p.code: p for p in (ESSENTIAL, PROFESSIONAL, ENTERPRISE)}


class Subscription(BaseModel):
    """Assinatura de um tenant a um plano, com add-ons e limites negociados."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: Identifier = Field(default_factory=new_id)
    client_id: Identifier
    plan_code: str
    status: SubscriptionStatus = SubscriptionStatus.TRIAL
    starts_at: datetime
    ends_at: datetime | None = None
    #: Add-ons vendidos por fora do plano base.
    extra_features: frozenset[Feature] = frozenset()
    #: Funcionalidades removidas por decisão contratual do próprio cliente.
    excluded_features: frozenset[Feature] = frozenset()
    #: Cotas renegociadas, sobrepõem as do plano.
    quota_overrides: dict[Quota, int] = Field(default_factory=dict)
    notes: str | None = None

    @field_validator("starts_at", "ends_at")
    @classmethod
    def _utc(cls, value: datetime | None) -> datetime | None:
        return None if value is None else ensure_utc(value)

    def is_current(self, moment: datetime) -> bool:
        moment = ensure_utc(moment)
        if not self.status.grants_access:
            return False
        if moment < self.starts_at:
            return False
        return self.ends_at is None or moment < self.ends_at


@dataclass(frozen=True, slots=True)
class Entitlements:
    """Resultado da resolução comercial para um tenant, num instante."""

    client_id: str
    plan_code: str | None
    status: SubscriptionStatus | None
    features: frozenset[Feature] = frozenset()
    quotas: dict[Quota, int] = field(default_factory=dict)

    @property
    def active(self) -> bool:
        return self.plan_code is not None

    def has(self, feature: Feature) -> bool:
        return feature in self.features

    def quota(self, quota: Quota) -> int:
        return self.quotas.get(quota, 0)

    def within_quota(self, quota: Quota, current_usage: int) -> bool:
        """`current_usage` é o consumo **antes** de adicionar mais um item."""
        limit = self.quota(quota)
        return limit == UNLIMITED or current_usage < limit

    def blocked_permissions(self) -> frozenset[Permission]:
        """Permissões que o plano não habilita, independentemente do papel."""
        return frozenset(
            permission
            for permission, feature in FEATURE_GATED_PERMISSIONS.items()
            if feature not in self.features
        )


NO_ENTITLEMENTS = Entitlements(client_id="", plan_code=None, status=None)


def resolve_entitlements(
    subscription: Subscription | None,
    moment: datetime,
    *,
    catalog: dict[str, Plan] | None = None,
) -> Entitlements:
    """Combina plano + add-ons + exclusões + cotas negociadas."""
    catalog = catalog if catalog is not None else PLAN_CATALOG

    if subscription is None or not subscription.is_current(moment):
        return Entitlements(
            client_id=subscription.client_id if subscription else "",
            plan_code=None,
            status=subscription.status if subscription else None,
        )

    plan = catalog.get(subscription.plan_code)
    if plan is None:
        # Plano removido do catálogo não vira acesso irrestrito por descuido.
        return Entitlements(
            client_id=subscription.client_id, plan_code=None, status=subscription.status
        )

    features = (plan.features | subscription.extra_features) - subscription.excluded_features
    quotas = {**plan.quotas, **subscription.quota_overrides}

    return Entitlements(
        client_id=subscription.client_id,
        plan_code=plan.code,
        status=subscription.status,
        features=frozenset(features),
        quotas=quotas,
    )
