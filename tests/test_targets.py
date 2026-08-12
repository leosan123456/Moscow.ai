"""Normalização de alvos — a camada onde um bypass de escopo costuma nascer."""

from __future__ import annotations

import pytest

from vulnai_shared.enums import TargetKind
from vulnai_shared.errors import InvalidTargetError
from vulnai_shared.targets import normalize_hostname, parse_target


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("API.ACME.example", "api.acme.example"),
        ("api.acme.example.", "api.acme.example"),
        ("  api.acme.example  ", "api.acme.example"),
    ],
)
def test_hostname_normalization(raw: str, expected: str) -> None:
    assert normalize_hostname(raw) == expected


def test_idn_hostname_vira_punycode() -> None:
    assert normalize_hostname("münchen.example") == "xn--mnchen-3ya.example"


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "-inicio.example",
        "fim-.example",
        "host..example",
        "a" * 70 + ".example",
        "192.168.0.1.5",  # TLD numérico: IP malformado disfarçado de nome
    ],
)
def test_hostname_invalido_e_rejeitado(raw: str) -> None:
    with pytest.raises(InvalidTargetError):
        normalize_hostname(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "0177.0.0.1",  # octal com zero à esquerda
        "2130706433",  # inteiro puro
        "203.0.113.999",
        "alvo com espaco.example",
        "ftp://acme.example",
        "http://acme.example:0",
        "http://acme.example:99999",
    ],
)
def test_formas_ambiguas_sao_rejeitadas(raw: str) -> None:
    with pytest.raises(InvalidTargetError):
        parse_target(raw)


def test_url_com_userinfo_e_recusada() -> None:
    # Clássico: parece apontar para o cliente, resolve para o atacante.
    with pytest.raises(InvalidTargetError):
        parse_target("http://api.acme.example@evil.tld/")


def test_parse_ip_com_porta() -> None:
    target = parse_target("203.0.113.10:8443")
    assert target.kind is TargetKind.IP
    assert target.value == "203.0.113.10:8443"
    assert target.port == 8443
    assert str(target.ip) == "203.0.113.10"


def test_parse_ipv6_com_e_sem_porta() -> None:
    assert parse_target("[2001:db8::1]:443").value == "[2001:db8::1]:443"
    assert parse_target("2001:db8::1").value == "2001:db8::1"


def test_parse_url_normaliza_host_e_path() -> None:
    target = parse_target("HTTPS://API.Acme.Example/v1/users")
    assert target.kind is TargetKind.URL
    assert target.value == "https://api.acme.example/v1/users"
    assert target.host == "api.acme.example"
    assert target.scheme == "https"


def test_parse_recurso_de_nuvem() -> None:
    account = parse_target("aws:123456789012")
    resource = parse_target("aws:123456789012/s3/bucket-de-logs")
    assert account.kind is TargetKind.CLOUD_ACCOUNT
    assert account.cloud_account == "123456789012"
    assert resource.kind is TargetKind.CLOUD_RESOURCE
    assert resource.cloud_resource == "s3/bucket-de-logs"
