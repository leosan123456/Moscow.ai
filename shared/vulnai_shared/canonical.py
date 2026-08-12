"""Serialização canônica e hashing.

Usada pelo digest de escopo, pela assinatura dos tokens e pela cadeia de auditoria.
Duas representações do mesmo fato precisam produzir exatamente os mesmos bytes, senão
a verificação de integridade vira ruído.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import date, datetime
from enum import Enum
from typing import Any


def _default(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, set | frozenset):
        return sorted(_default(v) if isinstance(v, Enum) else v for v in value)
    if isinstance(value, bytes):
        return b64encode(value)
    raise TypeError(f"tipo não serializável de forma canônica: {type(value)!r}")


def canonical_bytes(payload: Any) -> bytes:
    """JSON canônico: chaves ordenadas, sem espaço supérfluo, UTF-8."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_default,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_digest(payload: Any) -> str:
    """SHA-256 hex da forma canônica de `payload`."""
    return sha256_hex(canonical_bytes(payload))


def b64encode(data: bytes) -> str:
    """Base64 URL-safe sem padding — formato usado nos tokens."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)
