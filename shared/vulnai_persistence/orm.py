"""Esquema ORM.

Cada tabela guarda a entidade inteira serializada em `payload` (JSON) — a forma que os
modelos Pydantic já produzem via `model_dump(mode="json")` — mais um punhado de colunas
indexadas para as consultas que o sistema de fato faz (por tenant, por engagement, por
identidade natural usada em upsert). Essa é uma escolha deliberada: os objetos de valor
aninhados de cada agregado (`Scope`, `AuthorizationWindow`, `IntensityLimits`, ...) nunca
são consultados fora do agregado a que pertencem — são sempre lidos e escritos como uma
unidade — então reconstruí-los como tabelas relacionais só compraria complexidade sem
comprar nenhuma consulta nova. `model_dump(mode="json")` / `Model.model_validate(payload)`
preservam enum, datetime e tupla sem perda; o round-trip é exato.

Concorrência: cada repositório faz leitura-modificação-escrita dentro de uma única
transação por chamada, sem lock explícito. Correto para um único processo escrevendo por
tenant, que é a situação de hoje; sob múltiplos workers escrevendo o mesmo ativo ao mesmo
tempo, duas transações poderiam se sobrepor — resolver com `SELECT ... FOR UPDATE` fica
para quando essa situação existir de fato.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


# --------------------------------------------------------------------------------------
# Autorização
# --------------------------------------------------------------------------------------


class ClientRow(Base):
    __tablename__ = "clients"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(256))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class EngagementRow(Base):
    __tablename__ = "engagements"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class ApprovalRow(Base):
    __tablename__ = "human_approvals"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(128), index=True)
    engagement_id: Mapped[str] = mapped_column(String(128), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


# --------------------------------------------------------------------------------------
# Backoffice
# --------------------------------------------------------------------------------------


class UserRow(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class MembershipRow(Base):
    __tablename__ = "memberships"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(128), index=True)
    client_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    scope: Mapped[str] = mapped_column(String(16), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class SubscriptionRow(Base):
    __tablename__ = "subscriptions"

    #: Um cliente tem uma assinatura vigente por vez — mesma semântica do repositório
    #: em memória, que já sobrescrevia por `client_id`.
    client_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class ApiKeyRow(Base):
    __tablename__ = "api_keys"

    key_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    membership_id: Mapped[str] = mapped_column(String(128), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class SessionRow(Base):
    __tablename__ = "sessions"

    token_hash: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(128), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


# --------------------------------------------------------------------------------------
# Descoberta e coleta
# --------------------------------------------------------------------------------------


class AssetRow(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(128), index=True)
    engagement_id: Mapped[str] = mapped_column(String(128), index=True)
    identifier: Mapped[str] = mapped_column(String(512))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)

    __table_args__ = (
        UniqueConstraint("client_id", "identifier", name="uq_asset_client_identifier"),
    )


class ServiceRow(Base):
    __tablename__ = "services"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_id: Mapped[str] = mapped_column(String(128), index=True)
    protocol: Mapped[str] = mapped_column(String(8))
    port: Mapped[int] = mapped_column(Integer)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)

    __table_args__ = (
        UniqueConstraint(
            "client_id", "asset_id", "protocol", "port", name="uq_service_identity"
        ),
    )


class VulnerabilityRow(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    #: Catálogo compartilhado entre tenants — sem `client_id`, de propósito.
    cve_id: Mapped[str | None] = mapped_column(String(32), unique=True, index=True, nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(128), index=True)
    engagement_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_id: Mapped[str] = mapped_column(String(128), index=True)
    service_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    vulnerability_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    title: Mapped[str] = mapped_column(String(512))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)

    __table_args__ = (
        Index(
            "ix_finding_dedup", "client_id", "asset_id", "service_id", "vulnerability_id", "title"
        ),
    )


# --------------------------------------------------------------------------------------
# Auditoria
# --------------------------------------------------------------------------------------


class AuditEventRow(Base):
    """Espelha `vulnai_shared.audit.AuditEvent`. `sequence` é atribuído pelo `AuditLog`
    em processo (a cadeia de hash já precisa de ordem determinística), não pelo banco."""

    __tablename__ = "audit_events"

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    client_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    engagement_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
