"""esquema inicial

Cria todas as tabelas de `vulnai_persistence.orm`. Escrita à mão (não autogenerate):
cada tabela guarda a entidade como JSON (`payload`) mais as colunas indexadas usadas em
consulta — ver o docstring de `vulnai_persistence/orm.py` para a justificativa.

Revision ID: 0001
Revises:
Create Date: 2026-08-09
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "clients",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
    )

    op.create_table(
        "engagements",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("client_id", sa.String(128), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
    )
    op.create_index("ix_engagements_client_id", "engagements", ["client_id"])
    op.create_index("ix_engagements_status", "engagements", ["status"])

    op.create_table(
        "human_approvals",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("client_id", sa.String(128), nullable=False),
        sa.Column("engagement_id", sa.String(128), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
    )
    op.create_index("ix_human_approvals_client_id", "human_approvals", ["client_id"])
    op.create_index("ix_human_approvals_engagement_id", "human_approvals", ["engagement_id"])

    op.create_table(
        "users",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "memberships",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("user_id", sa.String(128), nullable=False),
        sa.Column("client_id", sa.String(128), nullable=True),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
    )
    op.create_index("ix_memberships_user_id", "memberships", ["user_id"])
    op.create_index("ix_memberships_client_id", "memberships", ["client_id"])
    op.create_index("ix_memberships_scope", "memberships", ["scope"])

    op.create_table(
        "subscriptions",
        sa.Column("client_id", sa.String(128), primary_key=True),
        sa.Column("payload", sa.JSON, nullable=False),
    )

    op.create_table(
        "api_keys",
        sa.Column("key_id", sa.String(64), primary_key=True),
        sa.Column("client_id", sa.String(128), nullable=True),
        sa.Column("membership_id", sa.String(128), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
    )
    op.create_index("ix_api_keys_client_id", "api_keys", ["client_id"])
    op.create_index("ix_api_keys_membership_id", "api_keys", ["membership_id"])

    op.create_table(
        "sessions",
        sa.Column("token_hash", sa.String(128), primary_key=True),
        sa.Column("user_id", sa.String(128), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])

    op.create_table(
        "assets",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("client_id", sa.String(128), nullable=False),
        sa.Column("engagement_id", sa.String(128), nullable=False),
        sa.Column("identifier", sa.String(512), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
        sa.UniqueConstraint("client_id", "identifier", name="uq_asset_client_identifier"),
    )
    op.create_index("ix_assets_client_id", "assets", ["client_id"])
    op.create_index("ix_assets_engagement_id", "assets", ["engagement_id"])

    op.create_table(
        "services",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("client_id", sa.String(128), nullable=False),
        sa.Column("asset_id", sa.String(128), nullable=False),
        sa.Column("protocol", sa.String(8), nullable=False),
        sa.Column("port", sa.Integer, nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
        sa.UniqueConstraint(
            "client_id", "asset_id", "protocol", "port", name="uq_service_identity"
        ),
    )
    op.create_index("ix_services_client_id", "services", ["client_id"])
    op.create_index("ix_services_asset_id", "services", ["asset_id"])

    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("cve_id", sa.String(32), nullable=True),
        sa.Column("payload", sa.JSON, nullable=False),
    )
    op.create_index("ix_vulnerabilities_cve_id", "vulnerabilities", ["cve_id"], unique=True)

    op.create_table(
        "findings",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("client_id", sa.String(128), nullable=False),
        sa.Column("engagement_id", sa.String(128), nullable=False),
        sa.Column("asset_id", sa.String(128), nullable=False),
        sa.Column("service_id", sa.String(128), nullable=True),
        sa.Column("vulnerability_id", sa.String(128), nullable=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
    )
    op.create_index("ix_findings_client_id", "findings", ["client_id"])
    op.create_index("ix_findings_engagement_id", "findings", ["engagement_id"])
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"])
    op.create_index(
        "ix_finding_dedup",
        "findings",
        ["client_id", "asset_id", "service_id", "vulnerability_id", "title"],
    )

    op.create_table(
        "audit_events",
        sa.Column("sequence", sa.Integer, primary_key=True, autoincrement=False),
        sa.Column("client_id", sa.String(128), nullable=True),
        sa.Column("engagement_id", sa.String(128), nullable=True),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
    )
    op.create_index("ix_audit_events_client_id", "audit_events", ["client_id"])
    op.create_index("ix_audit_events_engagement_id", "audit_events", ["engagement_id"])
    op.create_index("ix_audit_events_event_type", "audit_events", ["event_type"])


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("findings")
    op.drop_table("vulnerabilities")
    op.drop_table("services")
    op.drop_table("assets")
    op.drop_table("sessions")
    op.drop_table("api_keys")
    op.drop_table("subscriptions")
    op.drop_table("memberships")
    op.drop_table("users")
    op.drop_table("human_approvals")
    op.drop_table("engagements")
    op.drop_table("clients")
