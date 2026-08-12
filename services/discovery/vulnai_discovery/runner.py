"""Execução de ferramentas externas (nmap, subfinder, ...).

`ToolRunner` é o único ponto de contato com processos externos. Trocar a implementação
real por `FakeToolRunner` em teste evita que a suíte dependa de binário instalado na
máquina — e garante que nenhum teste dispara tráfego de rede de verdade contra um alvo.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from vulnai_discovery.errors import ToolNotAvailableError, ToolTimeoutError

DEFAULT_TIMEOUT = 120.0


@dataclass(frozen=True, slots=True)
class ToolResult:
    """Resultado bruto de uma execução — quem interpreta é o parser de cada ferramenta."""

    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class ToolRunner(Protocol):
    def run(self, command: Sequence[str], *, timeout: float = DEFAULT_TIMEOUT) -> ToolResult: ...


class SubprocessToolRunner:
    """Executa o binário de verdade. Nunca usado em teste automatizado."""

    def run(self, command: Sequence[str], *, timeout: float = DEFAULT_TIMEOUT) -> ToolResult:
        args = list(command)
        try:
            proc = subprocess.run(  # noqa: S603 - args vêm de build_*_command, não de input livre
                args, capture_output=True, text=True, timeout=timeout, check=False
            )
        except FileNotFoundError as exc:
            raise ToolNotAvailableError(f"ferramenta não encontrada: {args[0]!r}") from exc
        except subprocess.TimeoutExpired as exc:
            raise ToolTimeoutError(f"{args[0]} excedeu {timeout}s") from exc
        return ToolResult(
            command=tuple(args), returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr
        )


class FakeToolRunner:
    """Runner determinístico para teste.

    A saída é registrada por prefixo do comando (tipicamente `(binário,)`), então o teste
    não precisa reproduzir a linha de comando exata montada por `build_*_command`.
    Chamadas não roteadas levantam erro alto e claro em vez de silenciosamente devolver
    saída vazia — isso evita teste verde por acidente.
    """

    def __init__(self) -> None:
        self._scripted: dict[tuple[str, ...], ToolResult] = {}
        self.calls: list[tuple[str, ...]] = []

    def script(self, prefix: Sequence[str], result: ToolResult) -> None:
        self._scripted[tuple(prefix)] = result

    def run(self, command: Sequence[str], *, timeout: float = DEFAULT_TIMEOUT) -> ToolResult:
        command = tuple(command)
        self.calls.append(command)
        for prefix, result in self._scripted.items():
            if command[: len(prefix)] == prefix:
                return result
        raise AssertionError(f"FakeToolRunner: nenhum script casou com o comando {command!r}")
