"""`SqlAuditSink`: trilha de auditoria persistida em banco.

Implementa o mesmo protocolo `AuditSink` que `JsonlAuditSink` — `AuditLog` não sabe (nem
precisa saber) qual dos dois está por trás. A cadeia de hash é responsabilidade de
`AuditLog`; este sink só grava e relê registros na ordem de `sequence`, exatamente como o
sink em arquivo.
"""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from vulnai_shared.audit import AuditEvent
from vulnai_persistence.orm import AuditEventRow


class SqlAuditSink:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def append(self, event: AuditEvent) -> None:
        row = AuditEventRow(
            sequence=event.sequence,
            client_id=event.client_id,
            engagement_id=event.engagement_id,
            event_type=event.event_type.value,
            payload=event.payload() | {"event_hash": event.event_hash},
        )
        with self._sessions() as session:
            session.add(row)
            session.commit()

    def __iter__(self) -> Iterator[AuditEvent]:
        with self._sessions() as session:
            rows = session.scalars(select(AuditEventRow).order_by(AuditEventRow.sequence)).all()
            events = [AuditEvent.from_dict(row.payload) for row in rows]
        yield from events
