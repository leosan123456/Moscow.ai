"""Erros do serviço de coleta e enriquecimento."""

from __future__ import annotations

from vulnai_shared.errors import VulnAIError


class CollectionError(VulnAIError):
    """Base dos erros de coleta."""


class ToolNotAvailableError(CollectionError):
    """Binário da ferramenta não encontrado no `PATH`."""


class ToolTimeoutError(CollectionError):
    """Ferramenta excedeu o tempo limite."""


class ParseError(CollectionError):
    """Saída da ferramenta não pôde ser interpretada."""


class EnrichmentError(CollectionError):
    """Falha ao correlacionar um achado com CVE/NVD ou CISA KEV."""
