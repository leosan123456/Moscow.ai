"""Relógio injetável.

Todo componente sensível a tempo (janela de autorização, TTL de token, rate limit)
recebe um `Clock` por parâmetro. Nada na plataforma chama `datetime.now()` direto —
isso torna janelas e expirações testáveis de forma determinística.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

Clock = Callable[[], datetime]


def utcnow() -> datetime:
    """Agora, timezone-aware em UTC."""
    return datetime.now(UTC)


def ensure_utc(value: datetime) -> datetime:
    """Normaliza para UTC, rejeitando datetimes naive.

    Datetime naive é ambíguo e já causou janela de autorização errada em produção em
    projetos parecidos; aqui é erro explícito.
    """
    if value.tzinfo is None:
        raise ValueError("datetime naive não é aceito; use timezone-aware em UTC")
    return value.astimezone(UTC)


class FrozenClock:
    """Relógio controlado manualmente, para testes."""

    def __init__(self, start: datetime) -> None:
        self._now = ensure_utc(start)

    def __call__(self) -> datetime:
        return self._now

    def advance(self, seconds: float) -> datetime:
        self._now += timedelta(seconds=seconds)
        return self._now

    def set(self, value: datetime) -> datetime:
        self._now = ensure_utc(value)
        return self._now
