"""Modelo de dados core (M0).

Relações:
    Client 1--N Engagement, Engagement 1--1 Scope, Scope 1--N Asset,
    Asset 1--N Service, Service 1--N Finding, Finding N--1 Vulnerability,
    Finding 1--1 RiskScore, Engagement 1--N AuditEvent.

Multi-tenancy: toda entidade persistida carrega `client_id`. Consultas sem filtro por
`client_id` são consideradas bug de isolamento.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnai_shared.canonical import canonical_digest
from vulnai_shared.clock import ensure_utc, utcnow
from vulnai_shared.enums import (
    ActionClass,
    AssetCriticality,
    Confidence,
    EngagementStatus,
    FindingStatus,
    ScopeRuleEffect,
    ScopeRuleKind,
    Severity,
    TargetKind,
)

Identifier = Annotated[str, Field(min_length=1, max_length=128)]


def new_id() -> str:
    return str(uuid.uuid4())


class Entity(BaseModel):
    """Base das entidades: id, timestamps e imutabilidade por padrão."""

    model_config = ConfigDict(frozen=True, extra="forbid", use_enum_values=False)

    id: Identifier = Field(default_factory=new_id)
    created_at: datetime = Field(default_factory=utcnow)

    @field_validator("created_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class TenantEntity(Entity):
    """Entidade que pertence a um tenant. `client_id` nunca é opcional."""

    client_id: Identifier


# --------------------------------------------------------------------------------------
# Cliente, escopo e engajamento
# --------------------------------------------------------------------------------------


class Client(Entity):
    """Tenant. A raiz do isolamento de dados."""

    name: str = Field(min_length=1, max_length=256)
    legal_entity: str | None = None
    #: Contato responsável por autorizar engajamentos (regras de engajamento / LGPD).
    security_contact: str | None = None


class ScopeRule(BaseModel):
    """Uma linha do escopo contratado.

    `value` é normalizado na construção para que a comparação em runtime seja puramente
    textual — normalizar no momento da checagem convida a bypass por variação de forma.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: ScopeRuleKind
    value: str = Field(min_length=1, max_length=512)
    effect: ScopeRuleEffect = ScopeRuleEffect.INCLUDE
    #: Teto de intensidade para alvos que casam com esta regra. `None` = herda a engagement.
    max_action: ActionClass | None = None
    note: str | None = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def _normalize(self) -> ScopeRule:
        from vulnai_shared.targets import normalize_rule_value

        normalized = normalize_rule_value(self.kind, self.value)
        if normalized != self.value:
            object.__setattr__(self, "value", normalized)
        return self

    def __str__(self) -> str:
        return f"{self.effect.value}:{self.kind.value}:{self.value}"


class Scope(BaseModel):
    """Conjunto de regras do contrato. Exclusão vence inclusão, sempre."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rules: tuple[ScopeRule, ...] = ()
    #: Versão do escopo. Incrementa a cada alteração contratual; some no digest do token.
    version: int = Field(default=1, ge=1)

    @property
    def includes(self) -> tuple[ScopeRule, ...]:
        return tuple(r for r in self.rules if r.effect is ScopeRuleEffect.INCLUDE)

    @property
    def excludes(self) -> tuple[ScopeRule, ...]:
        return tuple(r for r in self.rules if r.effect is ScopeRuleEffect.EXCLUDE)

    def digest(self) -> str:
        """Digest estável do escopo, embutido no token de escopo.

        Se o contrato mudar, todo token emitido antes da mudança deixa de valer
        (`ScopeDriftError`) — evita varredura sob um escopo que já foi revisado.
        """
        payload = {
            "version": self.version,
            "rules": sorted(str(rule) for rule in self.rules),
        }
        return canonical_digest(payload)


class AuthorizationWindow(BaseModel):
    """Janela contratada de execução."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    starts_at: datetime
    ends_at: datetime

    @field_validator("starts_at", "ends_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @model_validator(mode="after")
    def _ordered(self) -> AuthorizationWindow:
        if self.ends_at <= self.starts_at:
            raise ValueError("ends_at deve ser posterior a starts_at")
        return self

    def contains(self, moment: datetime) -> bool:
        return self.starts_at <= ensure_utc(moment) < self.ends_at


class IntensityLimits(BaseModel):
    """Limites para nunca degradar o ambiente do cliente."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    #: Requisições por segundo por alvo (token bucket).
    requests_per_second_per_target: float = Field(default=5.0, gt=0, le=1000)
    #: Rajada máxima acumulável por alvo.
    burst_per_target: int = Field(default=10, ge=1, le=10_000)
    #: Alvos simultâneos por engajamento.
    max_concurrent_targets: int = Field(default=16, ge=1, le=4096)


class IntrusiveAuthorization(BaseModel):
    """Opt-in explícito para verificações intrusivas.

    Existe separado da engagement de propósito: intrusivo é exceção, tem janela própria,
    aprovador nomeado e referência ao documento de autorização.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    approved_by: str = Field(min_length=1, max_length=256)
    approval_reference: str = Field(min_length=1, max_length=256)
    window: AuthorizationWindow
    #: Restringe o opt-in a alvos específicos. Vazio = todo o escopo da engagement.
    limited_to: tuple[str, ...] = ()
    justification: str = Field(min_length=1, max_length=2048)


class Engagement(TenantEntity):
    """Ordem de serviço: liga cliente, escopo, janela e limites."""

    name: str = Field(min_length=1, max_length=256)
    contract_reference: str = Field(min_length=1, max_length=256)
    status: EngagementStatus = EngagementStatus.DRAFT
    scope: Scope
    window: AuthorizationWindow
    limits: IntensityLimits = Field(default_factory=IntensityLimits)
    #: Teto de intensidade da engagement inteira. Não destrutivo por padrão.
    max_action: ActionClass = ActionClass.ACTIVE_NON_INTRUSIVE
    intrusive_authorization: IntrusiveAuthorization | None = None
    rules_of_engagement_uri: str | None = None

    @model_validator(mode="after")
    def _intrusive_requires_optin(self) -> Engagement:
        if self.max_action is ActionClass.INTRUSIVE and self.intrusive_authorization is None:
            raise ValueError(
                "max_action=INTRUSIVE exige intrusive_authorization registrada "
                "(princípio non_destructive_default)"
            )
        return self

    def is_open(self, moment: datetime) -> bool:
        return self.status is EngagementStatus.ACTIVE and self.window.contains(moment)


# --------------------------------------------------------------------------------------
# Inventário
# --------------------------------------------------------------------------------------


class Asset(TenantEntity):
    """Ativo descoberto dentro do escopo (M1 popula, M0 apenas define)."""

    engagement_id: Identifier
    kind: TargetKind
    #: Forma normalizada do alvo — a mesma usada pelo gate de autorização.
    identifier: str = Field(min_length=1, max_length=512)
    hostnames: tuple[str, ...] = ()
    addresses: tuple[str, ...] = ()
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    tags: tuple[str, ...] = ()
    first_seen_at: datetime = Field(default_factory=utcnow)
    last_seen_at: datetime = Field(default_factory=utcnow)


class Service(TenantEntity):
    """Serviço exposto por um ativo."""

    asset_id: Identifier
    port: int = Field(ge=1, le=65535)
    protocol: str = Field(default="tcp", pattern=r"^(tcp|udp|sctp)$")
    product: str | None = None
    version: str | None = None
    #: CPE 2.3 quando conhecido — chave de correlação com CVE/NVD.
    cpe: str | None = None
    banner: str | None = Field(default=None, max_length=4096)


# --------------------------------------------------------------------------------------
# Vulnerabilidade, achado e risco
# --------------------------------------------------------------------------------------


class Vulnerability(Entity):
    """Vulnerabilidade catalogada (CVE/NVD). Compartilhada entre tenants — sem client_id."""

    cve_id: str | None = Field(default=None, pattern=r"^CVE-\d{4}-\d{4,}$")
    title: str = Field(min_length=1, max_length=512)
    description: str | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    #: Probabilidade de exploração (EPSS), usada na priorização.
    epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    #: Presença no catálogo CISA Known Exploited Vulnerabilities.
    in_cisa_kev: bool = False
    references: tuple[str, ...] = ()
    published_at: datetime | None = None


class RiskScore(BaseModel):
    """Saída do motor de priorização (M4). `value` em 0-100."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    value: float = Field(ge=0.0, le=100.0)
    severity: Severity
    #: Contribuição de cada fator, para o relatório explicar a nota.
    factors: dict[str, float] = Field(default_factory=dict)
    model_version: str | None = None
    computed_at: datetime = Field(default_factory=utcnow)


class Finding(TenantEntity):
    """Achado: uma vulnerabilidade observada num serviço específico."""

    engagement_id: Identifier
    asset_id: Identifier
    service_id: Identifier | None = None
    vulnerability_id: Identifier | None = None
    title: str = Field(min_length=1, max_length=512)
    description: str | None = None
    severity: Severity = Severity.NONE
    confidence: Confidence = Confidence.TENTATIVE
    status: FindingStatus = FindingStatus.NEW
    #: Como o achado foi obtido — prova não destrutiva (banner, header, config).
    evidence: str | None = Field(default=None, max_length=16_384)
    source_tool: str | None = None
    risk: RiskScore | None = None
    #: Rótulo do analista; alimenta o retreino do núcleo de IA (loop de feedback).
    analyst_label: FindingStatus | None = None


class Report(TenantEntity):
    """Relatório gerado para um stakeholder (M5)."""

    engagement_id: Identifier
    audience: str = Field(default="technical", pattern=r"^(executive|technical)$")
    finding_ids: tuple[str, ...] = ()
    summary: str | None = None
    generated_by: str | None = None
