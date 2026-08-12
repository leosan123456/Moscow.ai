"""Limite de intensidade por alvo (token bucket).

O limite é por `(engagement, alvo)`: dois engajamentos do mesmo cliente não somam
pressão sobre o mesmo host, e um alvo frágil não é penalizado pelo volume de outro.
O relógio é injetado para que o teste não dependa de `sleep`.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from vulnai_shared.clock import Clock, utcnow
from vulnai_shared.models import IntensityLimits


@dataclass
class _Bucket:
    tokens: float
    updated_at: float


class TokenBucketLimiter:
    """Token bucket em memória.

    Em produção com múltiplas réplicas, trocar por um backend compartilhado (Redis) —
    a interface `acquire`/`retry_after` foi mantida mínima justamente para isso.
    """

    def __init__(self, *, clock: Clock = utcnow) -> None:
        self._clock = clock
        self._buckets: dict[tuple[str, str], _Bucket] = {}
        self._lock = threading.Lock()

    def acquire(self, engagement_id: str, target: str, limits: IntensityLimits) -> bool:
        """Consome um token. `False` quando o limite foi atingido."""
        key = (engagement_id, target)
        now = self._clock().timestamp()
        rate = limits.requests_per_second_per_target
        capacity = float(limits.burst_per_target)

        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=capacity, updated_at=now)
                self._buckets[key] = bucket
            else:
                elapsed = max(0.0, now - bucket.updated_at)
                bucket.tokens = min(capacity, bucket.tokens + elapsed * rate)
                bucket.updated_at = now

            if bucket.tokens < 1.0:
                return False
            bucket.tokens -= 1.0
            return True

    def retry_after(self, engagement_id: str, target: str, limits: IntensityLimits) -> float:
        """Segundos até o próximo token ficar disponível."""
        with self._lock:
            bucket = self._buckets.get((engagement_id, target))
        if bucket is None or bucket.tokens >= 1.0:
            return 0.0
        return (1.0 - bucket.tokens) / limits.requests_per_second_per_target

    def reset(self, engagement_id: str | None = None) -> None:
        with self._lock:
            if engagement_id is None:
                self._buckets.clear()
                return
            for key in [k for k in self._buckets if k[0] == engagement_id]:
                del self._buckets[key]
