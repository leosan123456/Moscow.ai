"""Parsers de descoberta: comando montado e interpretação de saída de ferramenta."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnai_discovery.errors import ParseError
from vulnai_discovery.nmap import build_command, parse_xml
from vulnai_discovery.subdomains import build_command as build_subfinder_command
from vulnai_discovery.subdomains import parse_hostnames

FIXTURES = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------------------- nmap


def test_build_command_padrao_nao_passa_flag_de_porta() -> None:
    command = build_command("api.acme.example")
    assert command == ["nmap", "-oX", "-", "-Pn", "-sV", "api.acme.example"]


def test_build_command_todas_as_portas() -> None:
    command = build_command("api.acme.example", ports="all")
    assert "-p-" in command


def test_build_command_lista_explicita_de_portas() -> None:
    command = build_command("api.acme.example", ports="80,443")
    assert "-p" in command
    assert command[command.index("-p") + 1] == "80,443"


def test_build_command_sem_deteccao_de_servico() -> None:
    assert "-sV" not in build_command("api.acme.example", service_detection=False)


def test_parse_xml_ignora_porta_fechada_e_filtrada() -> None:
    xml_text = (FIXTURES / "nmap_scan.xml").read_text(encoding="utf-8")
    hosts = parse_xml(xml_text)

    assert len(hosts) == 1
    host = hosts[0]
    assert host.address == "203.0.113.10"
    assert host.hostnames == ("api.acme.example",)
    assert [p.port for p in host.ports] == [443]  # 22 fechada, 8080 filtrada — fora


def test_parse_xml_extrai_fingerprint_de_servico() -> None:
    xml_text = (FIXTURES / "nmap_scan.xml").read_text(encoding="utf-8")
    port = parse_xml(xml_text)[0].ports[0]

    assert port.product == "nginx"
    assert port.version == "1.24.0"
    assert port.cpe == "cpe:/a:nginx:nginx:1.24.0"
    assert port.protocol == "tcp"


def test_parse_xml_host_down_nao_aparece() -> None:
    xml_text = (FIXTURES / "nmap_host_down.xml").read_text(encoding="utf-8")
    assert parse_xml(xml_text) == []


def test_parse_xml_vazio_levanta_parse_error() -> None:
    with pytest.raises(ParseError):
        parse_xml("")


def test_parse_xml_malformado_levanta_parse_error() -> None:
    with pytest.raises(ParseError, match="inválido"):
        parse_xml("<nmaprun><host>")


# ------------------------------------------------------------------------ subdomínios


def test_build_subfinder_command() -> None:
    assert build_subfinder_command("acme.example") == [
        "subfinder",
        "-d",
        "acme.example",
        "-silent",
    ]


def test_parse_hostnames_normaliza_deduplica_e_descarta_lixo() -> None:
    texto = (FIXTURES / "subfinder_output.txt").read_text(encoding="utf-8")
    hosts = parse_hostnames(texto)

    # "API.Acme.Example" normaliza para o mesmo valor de "api.acme.example" -> dedup.
    assert hosts.count("api.acme.example") == 1
    assert "*.acme.example" not in hosts
    assert "www.acme.example" in hosts
    assert "staging.acme.example" in hosts


def test_parse_hostnames_linha_invalida_nao_derruba_o_parser() -> None:
    hosts = parse_hostnames("api.acme.example\n--- log de ruído ---\nwww.acme.example\n")
    assert hosts == ("api.acme.example", "www.acme.example")


def test_parse_hostnames_preserva_ordem_de_primeira_aparicao() -> None:
    hosts = parse_hostnames("b.acme.example\na.acme.example\nb.acme.example\n")
    assert hosts == ("b.acme.example", "a.acme.example")
