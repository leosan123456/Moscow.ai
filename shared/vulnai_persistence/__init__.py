"""Camada de persistência: SQLAlchemy sobre PostgreSQL (ou SQLite, para desenvolvimento).

Cada módulo implementa os `Protocol`s de repositório que os serviços já definiam para os
repositórios em memória — trocar `InMemoryX` por `SqlX` não muda o serviço que os usa,
só a montagem (ver `demo_m1.py`).
"""

from vulnai_persistence.audit import SqlAuditSink
from vulnai_persistence.authorization import SqlApprovalRepository, SqlEngagementRepository
from vulnai_persistence.backoffice import (
    SqlApiKeyRepository,
    SqlClientRepository,
    SqlMembershipRepository,
    SqlSessionRepository,
    SqlSubscriptionRepository,
    SqlUserRepository,
)
from vulnai_persistence.collection import SqlFindingRepository, SqlVulnerabilityRepository
from vulnai_persistence.discovery import SqlAssetRepository, SqlServiceRepository
from vulnai_persistence.engine import build_engine, build_session_factory, create_all, session_scope
from vulnai_persistence.orm import Base

__all__ = [
    "Base",
    "SqlApiKeyRepository",
    "SqlApprovalRepository",
    "SqlAssetRepository",
    "SqlAuditSink",
    "SqlClientRepository",
    "SqlEngagementRepository",
    "SqlFindingRepository",
    "SqlMembershipRepository",
    "SqlServiceRepository",
    "SqlSessionRepository",
    "SqlSubscriptionRepository",
    "SqlUserRepository",
    "SqlVulnerabilityRepository",
    "build_engine",
    "build_session_factory",
    "create_all",
    "session_scope",
]
