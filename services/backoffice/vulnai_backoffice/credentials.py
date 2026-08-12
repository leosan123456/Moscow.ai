"""Senhas e chaves de API.

Só stdlib: `hashlib.scrypt` para senha (memory-hard, resiste a GPU) e SHA-256 sobre um
segredo de alta entropia para chave de API — chave gerada por nós tem 256 bits de
entropia, então esticar o hash não acrescenta nada; o custo por requisição, sim.

A chave em claro só existe uma vez, no retorno da criação. O banco guarda o hash.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from vulnai_shared.canonical import b64decode, b64encode

# Parâmetros scrypt (OWASP: n=2^15, r=8, p=1 para uso interativo).
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SALT_BYTES = 16

_API_KEY_PREFIX = "vak"
_API_KEY_ID_BYTES = 8
_API_KEY_SECRET_BYTES = 32

MIN_PASSWORD_LENGTH = 12


class PasswordPolicyError(ValueError):
    """Senha não atende à política mínima."""


def hash_password(password: str) -> str:
    """Gera `scrypt$n$r$p$salt$hash`."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"senha precisa de ao menos {MIN_PASSWORD_LENGTH} caracteres"
        )
    salt = secrets.token_bytes(_SALT_BYTES)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
        maxmem=_SCRYPT_N * _SCRYPT_R * 256,
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${b64encode(salt)}${b64encode(derived)}"


def verify_password(password: str, encoded: str | None) -> bool:
    """Verificação em tempo constante.

    `encoded=None` (usuário só convidado, sem senha) retorna `False` — mas só depois de
    derivar um hash descartável, para que "usuário não existe" e "senha errada" levem o
    mesmo tempo e não virem um oráculo de enumeração de contas.
    """
    if not encoded:
        _dummy_work(password)
        return False

    try:
        algorithm, n, r, p, salt_b64, hash_b64 = encoded.split("$")
        if algorithm != "scrypt":
            return False
        salt = b64decode(salt_b64)
        expected = b64decode(hash_b64)
        derived = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
            maxmem=int(n) * int(r) * 256,
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(derived, expected)


def _dummy_work(password: str) -> None:
    hashlib.scrypt(
        password.encode("utf-8"),
        salt=b"\x00" * _SALT_BYTES,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
        maxmem=_SCRYPT_N * _SCRYPT_R * 256,
    )


def generate_api_key() -> tuple[str, str, str]:
    """Gera uma chave nova.

    Retorna `(chave_em_claro, key_id, secret_hash)`. O `key_id` viaja em claro dentro da
    chave para que a busca no banco seja por índice, sem varrer hashes.
    """
    key_id = secrets.token_hex(_API_KEY_ID_BYTES)
    secret = secrets.token_urlsafe(_API_KEY_SECRET_BYTES)
    return f"{_API_KEY_PREFIX}_{key_id}_{secret}", key_id, hash_api_secret(secret)


def hash_api_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def split_api_key(raw: str) -> tuple[str, str] | None:
    """Extrai `(key_id, secret)` de uma chave apresentada. `None` se o formato não bate."""
    parts = raw.split("_", 2)
    if len(parts) != 3 or parts[0] != _API_KEY_PREFIX or not parts[1] or not parts[2]:
        return None
    return parts[1], parts[2]


def verify_api_secret(secret: str, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_api_secret(secret), expected_hash)
