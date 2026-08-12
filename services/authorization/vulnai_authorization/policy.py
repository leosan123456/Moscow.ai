"""Política de segurança independente do escopo.

Existe uma segunda barreira além do contrato: mesmo que um alvo esteja formalmente no
escopo, há endereços que a plataforma se recusa a tocar por padrão porque atingi-los
quase sempre significa que algo foi normalizado errado ou que o scanner está sendo
usado para pivotar contra a própria infraestrutura.

Ranges privados (RFC1918) **não** são bloqueados: engajamento interno é caso de uso
legítimo e comum. O que é bloqueado é loopback, link-local (incluindo o endpoint de
metadados de nuvem, 169.254.169.254), multicast e reservados.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from vulnai_shared.enums import ActionClass
from vulnai_shared.errors import SafetyPolicyError
from vulnai_shared.targets import IPNetwork, Target

#: Endpoint de metadados de instância — alvo clássico de SSRF, nunca varrido por padrão.
CLOUD_METADATA_NETWORKS: tuple[str, ...] = ("169.254.169.254/32", "fd00:ec2::254/128")

DEFAULT_BLOCKED_NETWORKS: tuple[str, ...] = (
    "127.0.0.0/8",
    "::1/128",
    "169.254.0.0/16",
    "fe80::/10",
    "224.0.0.0/4",
    "ff00::/8",
    "0.0.0.0/8",
    "240.0.0.0/4",
    *CLOUD_METADATA_NETWORKS,
)

#: Nomes que resolvem para a própria máquina; bloqueados junto com o loopback.
DEFAULT_BLOCKED_HOSTNAMES: frozenset[str] = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost", "metadata.google.internal"}
)


@dataclass(frozen=True)
class SafetyPolicy:
    """Barreira aplicada antes e depois da checagem de escopo."""

    blocked_networks: tuple[IPNetwork, ...] = field(
        default_factory=lambda: tuple(
            ipaddress.ip_network(cidr) for cidr in DEFAULT_BLOCKED_NETWORKS
        )
    )
    blocked_hostnames: frozenset[str] = DEFAULT_BLOCKED_HOSTNAMES
    #: Teto global da plataforma. Nenhum contrato consegue autorizar acima disto.
    platform_max_action: ActionClass = ActionClass.INTRUSIVE
    #: Ação intrusiva exige aprovação humana registrada, além do opt-in contratual.
    require_human_approval_for_intrusive: bool = True

    def check(self, target: Target) -> None:
        """Levanta `SafetyPolicyError` se o alvo for proibido por política."""
        if target.host and target.host.lower() in self.blocked_hostnames:
            raise SafetyPolicyError(
                f"host {target.host!r} bloqueado por política de segurança da plataforma"
            )
        if target.ip is not None:
            for network in self.blocked_networks:
                if target.ip.version == network.version and target.ip in network:
                    raise SafetyPolicyError(
                        f"endereço {target.ip} pertence a {network}, bloqueado por política"
                    )

    def with_allowed(self, *networks: str) -> SafetyPolicy:
        """Deriva uma política liberando redes específicas (exceção deve ser explícita)."""
        allowed = {ipaddress.ip_network(net) for net in networks}
        return SafetyPolicy(
            blocked_networks=tuple(n for n in self.blocked_networks if n not in allowed),
            blocked_hostnames=self.blocked_hostnames,
            platform_max_action=self.platform_max_action,
            require_human_approval_for_intrusive=self.require_human_approval_for_intrusive,
        )


DEFAULT_SAFETY_POLICY = SafetyPolicy()
