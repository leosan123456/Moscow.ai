"""Repositórios do serviço de autorização.

Protocolos + implementações em memória. Trocar por Postgres depois não altera o gate:
o `AuthorizationService` só conhece estas interfaces.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vulnai_shared.clock import ensure_utc
from vulnai_shared.enums import ActionClass
from vulnai_shared.errors import TenantMismatchError
from vulnai_shared.models import Engagement, Identifier, new_id


class HumanApproval(BaseModel):
    """Aprovação humana registrada para uma ação específica.

    Princípio `human_in_the_loop`: nada além de leitura/observação acontece sem um destes.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: Identifier = Field(default_factory=new_id)
    client_id: Identifier
    engagement_id: Identifier
    #: Alvo normalizado, ou `"*"` para toda a engagement.
    target: str = "*"
    action: ActionClass
    approved_by: str = Field(min_length=1, max_length=256)
    reference: str = Field(min_length=1, max_length=256)
    granted_at: datetime
    expires_at: datetime
    revoked: bool = False

    @field_validator("granted_at", "expires_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    def covers(self, target: str, action: ActionClass, moment: datetime) -> bool:
        if self.revoked:
            return False
        if not self.granted_at <= ensure_utc(moment) < self.expires_at:
            return False
        if not self.action.dominates(action):
            return False
        return self.target == "*" or self.target == target


class EngagementRepository(Protocol):
    def get(self, engagement_id: str) -> Engagement | None: ...

    def save(self, engagement: Engagement) -> Engagement: ...

    def list_for_client(self, client_id: str) -> list[Engagement]: ...


class ApprovalRepository(Protocol):
    def find(
        self, engagement_id: str, target: str, action: ActionClass, moment: datetime
    ) -> HumanApproval | None: ...

    def save(self, approval: HumanApproval) -> HumanApproval: ...


class InMemoryEngagementRepository:
    """Repositório em memória com isolamento de tenant explícito nas leituras por cliente."""

    def __init__(self, engagements: list[Engagement] | None = None) -> None:
        self._items: dict[str, Engagement] = {e.id: e for e in (engagements or [])}

    def get(self, engagement_id: str) -> Engagement | None:
        return self._items.get(engagement_id)

    def get_for_client(self, engagement_id: str, client_id: str) -> Engagement | None:
        """Leitura com tenant obrigatório — use esta no caminho de API."""
        engagement = self._items.get(engagement_id)
        if engagement is None:
            return None
        if engagement.client_id != client_id:
            raise TenantMismatchError(
                f"engagement {engagement_id} não pertence ao cliente {client_id}"
            )
        return engagement

    def save(self, engagement: Engagement) -> Engagement:
        self._items[engagement.id] = engagement
        return engagement

    def list_for_client(self, client_id: str) -> list[Engagement]:
        return [e for e in self._items.values() if e.client_id == client_id]


class InMemoryApprovalRepository:
    def __init__(self, approvals: list[HumanApproval] | None = None) -> None:
        self._items: list[HumanApproval] = list(approvals or [])

    def find(
        self, engagement_id: str, target: str, action: ActionClass, moment: datetime
    ) -> HumanApproval | None:
        for approval in self._items:
            if approval.engagement_id != engagement_id:
                continue
            if approval.covers(target, action, moment):
                return approval
        return None

    def save(self, approval: HumanApproval) -> HumanApproval:
        self._items.append(approval)
        return approval
