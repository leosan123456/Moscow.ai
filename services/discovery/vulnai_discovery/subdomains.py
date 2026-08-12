"""Adaptador de enumeração de subdomínios (formato subfinder/amass: um host por linha)."""

from __future__ import annotations

from vulnai_shared.errors import InvalidTargetError
from vulnai_shared.targets import normalize_hostname


def build_command(apex_domain: str, *, silent: bool = True) -> list[str]:
    command = ["subfinder", "-d", apex_domain]
    if silent:
        command.append("-silent")
    return command


def parse_hostnames(text: str) -> tuple[str, ...]:
    """Interpreta a saída, descartando linhas inválidas em silêncio.

    Ferramentas de enumeração devolvem ruído ocasional (linha de log misturada à saída,
    wildcard `*.example.com`) — isso não deve derrubar a descoberta inteira. A
    normalização é a mesma usada pelo gate, então o resultado já está pronto para
    `ScopeGuard.partition`.
    """
    hosts: list[str] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("*."):
            continue
        try:
            normalized = normalize_hostname(line)
        except InvalidTargetError:
            continue
        if normalized not in seen:
            seen.add(normalized)
            hosts.append(normalized)
    return tuple(hosts)
