"""`DiscoveryService`: orquestração da etapa `02_asset_discovery`.

Todo alvo passa por `ScopeGuard` antes de qualquer ferramenta rodar — sem exceção. O
runner é injetado: em produção, `SubprocessToolRunner` chama o binário de verdade; em
teste, um runner fake devolve saída gravada, então a suíte nunca dispara tráfego real.

Um `DiscoveryService` é construído para uma engagement específica (o `ScopeGuard` já
carrega o token daquela engagement) — não existe instância "genérica" que decida o tenant
a partir do alvo.
"""

from __future__ import annotations

from dataclasses import dataclass

from vulnai_shared.clock import Clock, utcnow
from vulnai_shared.enums import ActionClass, AssetCriticality, TargetKind
from vulnai_shared.models import Asset, Service
from vulnai_shared.targets import Target
from vulnai_authorization import ScopeGuard, TargetRejection
from vulnai_discovery.cloud import CloudInventoryProvider
from vulnai_discovery.errors import ParseError
from vulnai_discovery.nmap import HostScanResult
from vulnai_discovery.nmap import build_command as build_nmap_command
from vulnai_discovery.nmap import parse_xml as parse_nmap_xml
from vulnai_discovery.repository import (
    AssetRepository,
    InMemoryAssetRepository,
    InMemoryServiceRepository,
    ServiceRepository,
)
from vulnai_discovery.runner import ToolRunner
from vulnai_discovery.subdomains import build_command as build_subfinder_command
from vulnai_discovery.subdomains import parse_hostnames


@dataclass(frozen=True, slots=True)
class SubdomainEnumerationResult:
    """Resultado de uma rodada de enumeração — inclui o que foi descartado, e por quê."""

    apex_domain: str
    discovered: tuple[str, ...]
    in_scope: tuple[str, ...]
    rejected: tuple[TargetRejection, ...]


class DiscoveryService:
    def __init__(
        self,
        *,
        guard: ScopeGuard,
        runner: ToolRunner,
        client_id: str,
        engagement_id: str,
        assets: AssetRepository | None = None,
        services: ServiceRepository | None = None,
        clock: Clock = utcnow,
    ) -> None:
        self._guard = guard
        self._runner = runner
        self._client_id = client_id
        self._engagement_id = engagement_id
        self._assets = assets or InMemoryAssetRepository()
        self._services = services or InMemoryServiceRepository()
        self._clock = clock

    # ------------------------------------------------------------- subdomínios
    def enumerate_subdomains(
        self, apex_domain: str, *, tool: str = "subfinder"
    ) -> SubdomainEnumerationResult:
        """Enumera subdomínios via fontes públicas (CT logs, agregadores de DNS).

        A consulta em si é passiva — não toca infraestrutura do cliente — mas o próprio
        domínio precisa estar no escopo contratado, e passar por `guard.touch` garante
        isso e deixa rastro de auditoria. Os hosts descobertos são então pré-filtrados
        contra o escopo em nível `ACTIVE_NON_INTRUSIVE`, o teto que `scan_host` vai
        exigir a seguir — assim o chamador já sabe exatamente o que pode varrer.
        """
        with self._guard.touch(apex_domain, ActionClass.PASSIVE, tool=tool) as target:
            command = build_subfinder_command(target.host or apex_domain)
            result = self._runner.run(command, timeout=120.0)

        discovered = parse_hostnames(result.stdout)
        in_scope, rejected = self._guard.partition(discovered, ActionClass.ACTIVE_NON_INTRUSIVE)
        return SubdomainEnumerationResult(
            apex_domain=apex_domain,
            discovered=discovered,
            in_scope=tuple(in_scope),
            rejected=tuple(rejected),
        )

    # ------------------------------------------------------------------ hosts
    def scan_host(
        self,
        raw_target: str,
        *,
        ports: str = "top-1000",
        criticality: AssetCriticality = AssetCriticality.MEDIUM,
        tool: str = "nmap",
    ) -> Asset:
        """Varre um alvo (TCP connect + detecção de serviço) e grava no inventário."""
        with self._guard.touch(raw_target, ActionClass.ACTIVE_NON_INTRUSIVE, tool=tool) as target:
            command = build_nmap_command(target.host, ports=ports)
            result = self._runner.run(command, timeout=300.0)

        if not result.ok:
            raise ParseError(f"{tool} terminou com código {result.returncode}: {result.stderr[:500]}")

        hosts = parse_nmap_xml(result.stdout)
        if not hosts:
            # Host respondeu à autorização de escopo mas não ao scan — comum quando um
            # firewall dropa tudo silenciosamente. Isso é dado (ativo inalcançável), não
            # falha de execução, mas também não há nada para gravar.
            raise ParseError(f"{tool} não reportou nenhum host ativo para {raw_target!r}")

        return self._save_host_scan(target, hosts[0], criticality)

    def _save_host_scan(
        self, target: Target, host: HostScanResult, criticality: AssetCriticality
    ) -> Asset:
        now = self._clock()
        hostnames = set(host.hostnames)
        addresses = {a for a in (host.address,) if a}
        if target.kind is TargetKind.HOSTNAME:
            hostnames.add(target.host)  # type: ignore[arg-type]
        else:
            addresses.add(target.host)  # type: ignore[arg-type]

        candidate = Asset(
            client_id=self._client_id,
            engagement_id=self._engagement_id,
            kind=target.kind,
            identifier=target.value,
            hostnames=tuple(sorted(hostnames)),
            addresses=tuple(sorted(addresses)),
            criticality=criticality,
            first_seen_at=now,
            last_seen_at=now,
        )
        asset = self._assets.upsert(candidate)

        for port in host.ports:
            service_candidate = Service(
                client_id=self._client_id,
                asset_id=asset.id,
                port=port.port,
                protocol=port.protocol,
                product=port.product,
                version=port.version,
                cpe=port.cpe,
            )
            self._services.upsert(service_candidate)

        return asset

    # ------------------------------------------------------------------ cloud
    def ingest_cloud_inventory(
        self, provider: CloudInventoryProvider, account_target: str, *, tool: str = "cloud-api"
    ) -> list[Asset]:
        """Registra os recursos de uma conta de nuvem como ativos.

        Consulta a API do provedor é passiva por natureza (não toca a carga do cliente),
        mas ainda exige que a conta esteja explicitamente no escopo contratado.
        """
        with self._guard.touch(account_target, ActionClass.PASSIVE, tool=tool) as target:
            if target.cloud_account is None or target.cloud_provider is None:
                raise ParseError(f"{account_target!r} não é uma conta de nuvem válida")
            resources = provider.list_resources(target.cloud_account)
            provider_name, account = target.cloud_provider, target.cloud_account

        now = self._clock()
        saved: list[Asset] = []
        for resource in resources:
            candidate = Asset(
                client_id=self._client_id,
                engagement_id=self._engagement_id,
                kind=TargetKind.CLOUD_RESOURCE,
                identifier=f"{provider_name}:{account}/{resource}",
                tags=(f"cloud:{provider_name}",),
                first_seen_at=now,
                last_seen_at=now,
            )
            saved.append(self._assets.upsert(candidate))
        return saved

    # --------------------------------------------------------------- consulta
    def inventory(self) -> list[Asset]:
        return self._assets.list_for_engagement(self._client_id, self._engagement_id)

    def services_of(self, asset_id: str) -> list[Service]:
        return self._services.list_for_asset(self._client_id, asset_id)
