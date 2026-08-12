"""Repositórios SQL do serviço de autorização (`EngagementRepository`, `ApprovalRepository`)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from vulnai_shared.enums import ActionClass
from vulnai_shared.models import Engagement
from vulnai_authorization.repository import HumanApproval
from vulnai_persistence.orm import ApprovalRow, EngagementRow


class SqlEngagementRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def get(self, engagement_id: str) -> Engagement | None:
        with self._sessions() as session:
            row = session.get(EngagementRow, engagement_id)
            return Engagement.model_validate(row.payload) if row else None

    def save(self, engagement: Engagement) -> Engagement:
        with self._sessions() as session:
            row = session.get(EngagementRow, engagement.id)
            payload = engagement.model_dump(mode="json")
            if row is None:
                session.add(
                    EngagementRow(
                        id=engagement.id,
                        client_id=engagement.client_id,
                        status=engagement.status.value,
                        payload=payload,
                    )
                )
            else:
                row.client_id = engagement.client_id
                row.status = engagement.status.value
                row.payload = payload
            session.commit()
        return engagement

    def list_for_client(self, client_id: str) -> list[Engagement]:
        with self._sessions() as session:
            rows = session.scalars(
                select(EngagementRow).where(EngagementRow.client_id == client_id)
            ).all()
            return [Engagement.model_validate(row.payload) for row in rows]


class SqlApprovalRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def find(
        self, engagement_id: str, target: str, action: ActionClass, moment: datetime
    ) -> HumanApproval | None:
        with self._sessions() as session:
            rows = session.scalars(
                select(ApprovalRow).where(ApprovalRow.engagement_id == engagement_id)
            ).all()
            for row in rows:
                approval = HumanApproval.model_validate(row.payload)
                if approval.covers(target, action, moment):
                    return approval
        return None

    def save(self, approval: HumanApproval) -> HumanApproval:
        with self._sessions() as session:
            session.merge(
                ApprovalRow(
                    id=approval.id,
                    client_id=approval.client_id,
                    engagement_id=approval.engagement_id,
                    payload=approval.model_dump(mode="json"),
                )
            )
            session.commit()
        return approval
