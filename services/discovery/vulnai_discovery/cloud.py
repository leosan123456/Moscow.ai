"""Inventário cloud (AWS/GCP/Azure) — contrato mínimo.

Implementações reais chamam a API do provedor (boto3, google-cloud, azure-mgmt) e ficam
fora deste repositório: exigem credenciais que este ambiente não tem como validar. O que
importa aqui é o contrato, para que a orquestração de descoberta seja testável sem SDK de
nuvem nenhum instalado.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol


class CloudInventoryProvider(Protocol):
    """Lista recursos de uma conta.

    Cada item é um caminho relativo à conta (`"s3/bucket-de-logs"`, `"ec2/i-0123abcd"`),
    sem o prefixo `provider:conta/` — quem monta o identificador completo é o chamador,
    que já sabe o provedor e a conta a partir do alvo autorizado.
    """

    def list_resources(self, account: str) -> Sequence[str]: ...


@dataclass(frozen=True, slots=True)
class StaticCloudInventoryProvider:
    """Provider fixo — para teste e para ambientes sem SDK de nuvem disponível."""

    resources_by_account: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def list_resources(self, account: str) -> Sequence[str]:
        return self.resources_by_account.get(account, ())
