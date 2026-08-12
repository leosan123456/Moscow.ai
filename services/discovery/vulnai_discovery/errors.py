"""Erros do serviço de descoberta."""

from __future__ import annotations

from vulnai_shared.errors import VulnAIError


class DiscoveryError(VulnAIError):
    """Base dos erros de descoberta."""


class ToolNotAvailableError(DiscoveryError):
    """Binário da ferramenta não encontrado no `PATH`."""


class ToolTimeoutError(DiscoveryError):
    """Ferramenta excedeu o tempo limite — normalmente sinal de alvo instável."""


class ParseError(DiscoveryError):
    """Saída da ferramenta não pôde ser interpretada, ou veio vazia."""
