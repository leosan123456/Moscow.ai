"""Descoberta de ativos — etapa `02_asset_discovery` do pipeline.

Todo alvo passa por `ScopeGuard` (de `vulnai_authorization`) antes de qualquer ferramenta
externa rodar. Este módulo nunca chama nmap/subfinder direto com uma string vinda de fora.
"""

from vulnai_discovery.cloud import CloudInventoryProvider, StaticCloudInventoryProvider
from vulnai_discovery.errors import DiscoveryError, ParseError, ToolNotAvailableError, ToolTimeoutError
from vulnai_discovery.nmap import DiscoveredPort, HostScanResult
from vulnai_discovery.repository import (
    AssetRepository,
    InMemoryAssetRepository,
    InMemoryServiceRepository,
    ServiceRepository,
)
from vulnai_discovery.runner import FakeToolRunner, SubprocessToolRunner, ToolResult, ToolRunner
from vulnai_discovery.service import DiscoveryService, SubdomainEnumerationResult

__all__ = [
    "AssetRepository",
    "CloudInventoryProvider",
    "DiscoveredPort",
    "DiscoveryError",
    "DiscoveryService",
    "FakeToolRunner",
    "HostScanResult",
    "InMemoryAssetRepository",
    "InMemoryServiceRepository",
    "ParseError",
    "ServiceRepository",
    "StaticCloudInventoryProvider",
    "SubdomainEnumerationResult",
    "SubprocessToolRunner",
    "ToolNotAvailableError",
    "ToolResult",
    "ToolRunner",
    "ToolTimeoutError",
]
