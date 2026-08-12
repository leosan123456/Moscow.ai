"""Trilha de auditoria: append-only e detecção de adulteração."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from vulnai_shared.audit import (
    GENESIS_HASH,
    AuditLog,
    InMemoryAuditSink,
    JsonlAuditSink,
    verify_chain,
)
from vulnai_shared.clock import FrozenClock
from vulnai_shared.enums import AuditEventType
from vulnai_shared.errors import AuditChainError


def _log(clock: FrozenClock) -> AuditLog:
    return AuditLog(InMemoryAuditSink(), clock=clock)


def test_cadeia_encadeia_do_genesis(clock: FrozenClock) -> None:
    log = _log(clock)
    primeiro = log.record(
        AuditEventType.ENGAGEMENT_CREATED, actor="admin", outcome="ok", client_id="cli-acme"
    )
    segundo = log.record(
        AuditEventType.SCOPE_UPDATED, actor="admin", outcome="ok", client_id="cli-acme"
    )

    assert primeiro.prev_hash == GENESIS_HASH
    assert primeiro.sequence == 1
    assert segundo.prev_hash == primeiro.event_hash
    assert segundo.sequence == 2
    assert log.head == segundo.event_hash
    assert log.verify() == 2


def test_adulteracao_de_conteudo_e_detectada(clock: FrozenClock) -> None:
    log = _log(clock)
    log.record(AuditEventType.AUTHORIZATION_ALLOWED, actor="a", outcome="allow", target="a.example")
    log.record(AuditEventType.AUTHORIZATION_ALLOWED, actor="a", outcome="allow", target="b.example")

    eventos = list(log)
    # Alguém tenta apagar o rastro de ter tocado b.example.
    forjado = replace(eventos[1], target="c.example")
    with pytest.raises(AuditChainError, match="adulterado"):
        verify_chain([eventos[0], forjado])


def test_remocao_de_evento_quebra_a_cadeia(clock: FrozenClock) -> None:
    log = _log(clock)
    for i in range(3):
        log.record(AuditEventType.ASSET_TOUCHED, actor="a", outcome="ok", target=f"{i}.example")

    eventos = list(log)
    with pytest.raises(AuditChainError):
        verify_chain([eventos[0], eventos[2]])


def test_reordenacao_quebra_a_cadeia(clock: FrozenClock) -> None:
    log = _log(clock)
    log.record(AuditEventType.ASSET_TOUCHED, actor="a", outcome="ok")
    log.record(AuditEventType.ASSET_TOUCHED, actor="a", outcome="ok")

    with pytest.raises(AuditChainError):
        verify_chain(list(log)[::-1])


def test_persistencia_jsonl_e_retomada(tmp_path: Path, clock: FrozenClock) -> None:
    caminho = tmp_path / "audit" / "trail.jsonl"

    primeiro = AuditLog(JsonlAuditSink(caminho), clock=clock)
    primeiro.record(AuditEventType.TOKEN_ISSUED, actor="admin", outcome="issued")
    primeiro.record(AuditEventType.AUTHORIZATION_ALLOWED, actor="admin", outcome="allow")

    # Processo reinicia e retoma a mesma cadeia, sem recomeçar do gênesis.
    segundo = AuditLog(JsonlAuditSink(caminho), clock=clock)
    assert segundo.head == primeiro.head
    terceiro = segundo.record(AuditEventType.REPORT_GENERATED, actor="admin", outcome="ok")

    assert terceiro.sequence == 3
    assert segundo.verify() == 3
    assert len(caminho.read_text(encoding="utf-8").strip().splitlines()) == 3


def test_arquivo_editado_na_mao_e_detectado(tmp_path: Path, clock: FrozenClock) -> None:
    caminho = tmp_path / "trail.jsonl"
    log = AuditLog(JsonlAuditSink(caminho), clock=clock)
    log.record(AuditEventType.ASSET_TOUCHED, actor="a", outcome="ok", target="alvo.example")
    log.record(AuditEventType.ASSET_TOUCHED, actor="a", outcome="ok", target="outro.example")

    linhas = caminho.read_text(encoding="utf-8").strip().splitlines()
    registro = json.loads(linhas[0])
    registro["target"] = "algo-inocente.example"
    linhas[0] = json.dumps(registro, sort_keys=True, ensure_ascii=False)
    caminho.write_text("\n".join(linhas) + "\n", encoding="utf-8")

    with pytest.raises(AuditChainError):
        verify_chain(JsonlAuditSink(caminho))
