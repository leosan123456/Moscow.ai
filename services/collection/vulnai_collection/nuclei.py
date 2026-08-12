"""Adaptador nuclei: fingerprint por template, achados não destrutivos.

O comando exclui explicitamente as famílias de template `dos`, `fuzz` e `intrusive` —
essas alterariam estado ou sobrecarregariam o alvo, o que pertence à classe `INTRUSIVE`
do gate, não a `ACTIVE_NON_INTRUSIVE`. Rodar um template dessas famílias exige o mesmo
opt-in contratual e aprovação humana que qualquer outra ação intrusiva.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from vulnai_collection.errors import ParseError

DEFAULT_TAGS = "cve,exposure,misconfig,default-login,tech"
EXCLUDED_TAGS = "dos,fuzz,intrusive"


@dataclass(frozen=True, slots=True)
class NucleiMatch:
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    cve_ids: tuple[str, ...]
    description: str | None = None
    references: tuple[str, ...] = ()


def build_command(
    target: str, *, tags: str = DEFAULT_TAGS, rate_limit: int = 50
) -> list[str]:
    """`rate_limit` (requisições/s do próprio nuclei) é uma segunda proteção, além do
    limite de intensidade do gate — as duas operam em camadas diferentes."""
    return [
        "nuclei",
        "-u",
        target,
        "-jsonl",
        "-silent",
        "-tags",
        tags,
        "-etags",
        EXCLUDED_TAGS,
        "-rate-limit",
        str(rate_limit),
    ]


def parse_jsonl(text: str) -> list[NucleiMatch]:
    """Uma linha JSON por achado. Nuclei sem match nenhum produz saída vazia — não é erro."""
    matches: list[NucleiMatch] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ParseError(f"linha {line_number} da saída do nuclei não é JSON válido") from exc

        info = record.get("info") or {}
        classification = info.get("classification") or {}
        matches.append(
            NucleiMatch(
                template_id=record.get("template-id", "?"),
                name=info.get("name") or record.get("template-id", "achado sem nome"),
                severity=info.get("severity", "unknown"),
                host=record.get("host", ""),
                matched_at=record.get("matched-at") or record.get("host", ""),
                cve_ids=tuple(classification.get("cve-id") or ()),
                description=info.get("description"),
                references=tuple(info.get("reference") or ()),
            )
        )
    return matches
