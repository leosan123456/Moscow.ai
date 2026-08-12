"""Correspondência de escopo: inclusão, exclusão e ausência de inferência entre tipos."""

from __future__ import annotations

import pytest

from vulnai_shared.enums import ActionClass, ScopeRuleEffect, ScopeRuleKind
from vulnai_shared.models import Scope, ScopeRule
from vulnai_shared.targets import parse_target
from vulnai_authorization import evaluate_scope


def _match(scope: Scope, raw: str) -> bool:
    return evaluate_scope(scope, parse_target(raw)).in_scope


@pytest.mark.parametrize(
    "raw",
    ["acme.example", "api.acme.example", "a.b.c.acme.example", "https://api.acme.example/v1"],
)
def test_regra_de_dominio_cobre_apex_e_subdominios(scope: Scope, raw: str) -> None:
    assert _match(scope, raw)


@pytest.mark.parametrize(
    "raw",
    [
        "evil-acme.example",  # sufixo sem fronteira de rótulo
        "acme.example.evil.tld",  # domínio contratado usado como prefixo
        "acmeexample",
        "outro.tld",
    ],
)
def test_dominio_parecido_nao_entra_no_escopo(scope: Scope, raw: str) -> None:
    assert not _match(scope, raw)


def test_cidr_cobre_a_faixa_contratada(scope: Scope) -> None:
    assert _match(scope, "203.0.113.10")
    assert _match(scope, "203.0.113.10:8080")
    assert not _match(scope, "203.0.114.10")
    assert not _match(scope, "198.51.100.1")


def test_exclusao_vence_inclusao(scope: Scope) -> None:
    # Está sob `acme.example`, mas foi excluído pelas regras de engajamento.
    assert not _match(scope, "pagamentos.acme.example")
    # Está no CIDR contratado, mas é o gateway do cliente.
    assert not _match(scope, "203.0.113.9")


def test_hostname_nao_casa_com_regra_de_cidr() -> None:
    """Sem resolução de DNS na decisão: quem controla o registro não controla o escopo."""
    scope = Scope(rules=(ScopeRule(kind=ScopeRuleKind.CIDR, value="203.0.113.0/24"),))
    assert not _match(scope, "acme.example")


def test_ip_nao_casa_com_regra_de_dominio() -> None:
    scope = Scope(rules=(ScopeRule(kind=ScopeRuleKind.DOMAIN, value="acme.example"),))
    assert not _match(scope, "203.0.113.10")


def test_url_prefix_respeita_fronteira_de_path() -> None:
    scope = Scope(
        rules=(ScopeRule(kind=ScopeRuleKind.URL_PREFIX, value="https://api.acme.example/v1"),)
    )
    assert _match(scope, "https://api.acme.example/v1")
    assert _match(scope, "https://api.acme.example/v1/users")
    assert not _match(scope, "https://api.acme.example/v10")
    assert not _match(scope, "https://api.acme.example/admin")
    assert not _match(scope, "http://api.acme.example/v1")  # esquema diferente


def test_teto_mais_restritivo_entre_regras_que_casam() -> None:
    scope = Scope(
        rules=(
            ScopeRule(
                kind=ScopeRuleKind.DOMAIN,
                value="acme.example",
                max_action=ActionClass.ACTIVE_NON_INTRUSIVE,
            ),
            ScopeRule(
                kind=ScopeRuleKind.HOSTNAME,
                value="frágil.acme.example".replace("á", "a"),
                max_action=ActionClass.PASSIVE,
            ),
        )
    )
    match = evaluate_scope(scope, parse_target("fragil.acme.example"))
    assert match.in_scope
    assert match.max_action is ActionClass.PASSIVE


def test_escopo_vazio_nega_tudo() -> None:
    assert not _match(Scope(), "acme.example")


def test_digest_muda_quando_o_escopo_muda(scope: Scope) -> None:
    outro = Scope(
        version=scope.version,
        rules=(
            *scope.rules,
            ScopeRule(
                kind=ScopeRuleKind.DOMAIN, value="novo.example", effect=ScopeRuleEffect.INCLUDE
            ),
        ),
    )
    assert scope.digest() != outro.digest()
    # E é estável para o mesmo conteúdo, independentemente da ordem das regras.
    reordenado = Scope(version=scope.version, rules=tuple(reversed(scope.rules)))
    assert scope.digest() == reordenado.digest()
