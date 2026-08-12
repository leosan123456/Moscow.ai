"""Coleta e enriquecimento — etapa `03_collection_enrichment` do pipeline.

Fingerprint e verificação de imagem passam por `ScopeGuard` como qualquer toque em
infraestrutura do cliente. Correlação com CVE/NVD e CISA KEV são catálogos públicos.
"""

from vulnai_collection.errors import CollectionError, EnrichmentError, ParseError, ToolNotAvailableError, ToolTimeoutError
from vulnai_collection.kev import HttpKevCatalog, KevCatalog, StaticKevCatalog
from vulnai_collection.nuclei import NucleiMatch
from vulnai_collection.nvd import CveRecord, HttpNvdClient, NvdClient, StaticNvdCatalog
from vulnai_collection.repository import (
    FindingRepository,
    InMemoryFindingRepository,
    InMemoryVulnerabilityRepository,
    VulnerabilityRepository,
)
from vulnai_collection.runner import FakeToolRunner, SubprocessToolRunner, ToolResult, ToolRunner
from vulnai_collection.service import CollectionService
from vulnai_collection.trivy import TrivyVulnerability

__all__ = [
    "CollectionError",
    "CollectionService",
    "CveRecord",
    "EnrichmentError",
    "FakeToolRunner",
    "FindingRepository",
    "HttpKevCatalog",
    "HttpNvdClient",
    "InMemoryFindingRepository",
    "InMemoryVulnerabilityRepository",
    "KevCatalog",
    "NucleiMatch",
    "NvdClient",
    "ParseError",
    "StaticKevCatalog",
    "StaticNvdCatalog",
    "SubprocessToolRunner",
    "ToolNotAvailableError",
    "ToolResult",
    "ToolRunner",
    "ToolTimeoutError",
    "TrivyVulnerability",
    "VulnerabilityRepository",
]
