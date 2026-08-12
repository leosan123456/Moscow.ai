"""Trilha de auditoria imutável.

Cada evento carrega `prev_hash` e um hash próprio sobre a forma canônica do registro.
Alterar ou remover um evento antigo quebra todos os hashes seguintes, o que
`verify_chain` detecta. A trilha é append-only: não existe update nem delete na API.

Persistência em JSONL por padrão (auditável com ferramentas comuns e fácil de espelhar
para storage WORM). O `AuditLog` aceita qualquer `AuditSink`, então trocar por Postgres
append-only ou S3 Object Lock não muda o chamador.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from vulnai_shared.canonical import canonical_bytes, sha256_hex
from vulnai_shared.clock import Clock, ensure_utc, utcnow
from vulnai_shared.enums import AuditEventType
from vulnai_shared.errors import AuditChainError
from vulnai_shared.models import new_id

#: Hash do "evento zero" — âncora da cadeia.
GENESIS_HASH = "0" * 64


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Registro imutável de algo que aconteceu com um ativo ou com uma autorização."""

    sequence: int
    event_type: AuditEventType
    occurred_at: datetime
    #: Tenant dono do evento. `None` só para eventos de plataforma (admin global).
    client_id: str | None
    engagement_id: str | None
    #: Quem causou o evento: usuário, chave de API ou serviço.
    actor: str
    #: Alvo normalizado, quando o evento tocou um ativo do cliente.
    target: str | None
    outcome: str
    details: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = GENESIS_HASH
    event_hash: str = ""
    id: str = field(default_factory=new_id)

    def payload(self) -> dict[str, Any]:
        """Parte assinada do registro — tudo menos o próprio hash."""
        return {
            "id": self.id,
            "sequence": self.sequence,
            "event_type": self.event_type.value,
            "occurred_at": ensure_utc(self.occurred_at).isoformat(),
            "client_id": self.client_id,
            "engagement_id": self.engagement_id,
            "actor": self.actor,
            "target": self.target,
            "outcome": self.outcome,
            "details": self.details,
            "prev_hash": self.prev_hash,
        }

    def compute_hash(self) -> str:
        return sha256_hex(canonical_bytes(self.payload()))

    def to_json(self) -> str:
        record = self.payload()
        record["event_hash"] = self.event_hash
        return json.dumps(record, sort_keys=True, ensure_ascii=False)

    @classmethod
    def from_dict(cls, record: dict[str, Any]) -> AuditEvent:
        return cls(
            id=record["id"],
            sequence=int(record["sequence"]),
            event_type=AuditEventType(record["event_type"]),
            occurred_at=datetime.fromisoformat(record["occurred_at"]),
            client_id=record.get("client_id"),
            engagement_id=record.get("engagement_id"),
            actor=record["actor"],
            target=record.get("target"),
            outcome=record["outcome"],
            details=record.get("details", {}),
            prev_hash=record["prev_hash"],
            event_hash=record.get("event_hash", ""),
        )


class AuditSink(Protocol):
    """Destino append-only de eventos."""

    def append(self, event: AuditEvent) -> None: ...

    def __iter__(self) -> Iterator[AuditEvent]: ...


class InMemoryAuditSink:
    """Sink em memória — usado em testes e em execução local."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        self._events.append(event)

    def __iter__(self) -> Iterator[AuditEvent]:
        return iter(tuple(self._events))

    def __len__(self) -> int:
        return len(self._events)


class JsonlAuditSink:
    """Sink em arquivo JSONL, com flush + fsync a cada evento.

    O fsync é deliberado: uma trilha que perde os últimos eventos num crash não serve
    como prova do que foi tocado no ambiente do cliente.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def append(self, event: AuditEvent) -> None:
        with self._lock, self._path.open("a", encoding="utf-8") as handle:
            handle.write(event.to_json() + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def __iter__(self) -> Iterator[AuditEvent]:
        if not self._path.exists():
            return
        with self._path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield AuditEvent.from_dict(json.loads(line))
                except (json.JSONDecodeError, KeyError, ValueError) as exc:
                    raise AuditChainError(
                        f"registro de auditoria corrompido em {self._path}:{line_number}"
                    ) from exc


class AuditLog:
    """API de escrita da trilha. Só existe `record` — não há update nem delete."""

    def __init__(self, sink: AuditSink | None = None, *, clock: Clock = utcnow) -> None:
        self._sink: AuditSink = sink if sink is not None else InMemoryAuditSink()
        self._clock = clock
        self._lock = threading.Lock()
        self._last_hash, self._sequence = self._resume()

    def _resume(self) -> tuple[str, int]:
        """Retoma a cadeia de um sink já populado (restart do processo)."""
        last_hash, sequence = GENESIS_HASH, 0
        for event in self._sink:
            last_hash, sequence = event.event_hash, event.sequence
        return last_hash, sequence

    @property
    def head(self) -> str:
        """Hash do último evento — âncora publicável para conferência externa."""
        return self._last_hash

    def record(
        self,
        event_type: AuditEventType,
        *,
        actor: str,
        outcome: str,
        client_id: str | None = None,
        engagement_id: str | None = None,
        target: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        with self._lock:
            event = AuditEvent(
                sequence=self._sequence + 1,
                event_type=event_type,
                occurred_at=self._clock(),
                client_id=client_id,
                engagement_id=engagement_id,
                actor=actor,
                target=target,
                outcome=outcome,
                details=dict(details or {}),
                prev_hash=self._last_hash,
            )
            event = _with_hash(event)
            self._sink.append(event)
            self._last_hash = event.event_hash
            self._sequence = event.sequence
            return event

    def __iter__(self) -> Iterator[AuditEvent]:
        return iter(self._sink)

    def verify(self) -> int:
        """Verifica a cadeia inteira. Retorna a quantidade de eventos válidos."""
        return verify_chain(self._sink)


def _with_hash(event: AuditEvent) -> AuditEvent:
    from dataclasses import replace

    return replace(event, event_hash=event.compute_hash())


def verify_chain(events: Iterable[AuditEvent]) -> int:
    """Revalida sequência, encadeamento e hash de cada evento.

    Levanta `AuditChainError` no primeiro registro inconsistente.
    """
    expected_prev = GENESIS_HASH
    expected_sequence = 1
    count = 0

    for event in events:
        if event.sequence != expected_sequence:
            raise AuditChainError(
                f"sequência quebrada: esperado {expected_sequence}, veio {event.sequence}"
            )
        if event.prev_hash != expected_prev:
            raise AuditChainError(
                f"encadeamento quebrado no evento {event.sequence}: "
                f"prev_hash {event.prev_hash!r} != {expected_prev!r}"
            )
        recomputed = event.compute_hash()
        if recomputed != event.event_hash:
            raise AuditChainError(
                f"hash inválido no evento {event.sequence}: registro foi adulterado"
            )
        expected_prev = event.event_hash
        expected_sequence += 1
        count += 1

    return count
