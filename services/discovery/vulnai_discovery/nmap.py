"""Adaptador nmap: monta a linha de comando e interpreta a saída XML.

A varredura é sempre TCP connect com `-Pn` (sem ping de descoberta — muitos ambientes de
cliente bloqueiam ICMP e um "host down" falso interromperia a coleta) e sem `-sS`: o scan
SYN exige root e é um passo mais furtivo/intrusivo do que o necessário para
`ACTIVE_NON_INTRUSIVE`. O connect scan completa o handshake e nada além disso.

Análise de XML: a saída vem do nosso próprio `nmap` local, não de payload do alvo — o
alvo só influencia valores de atributo (nome de serviço, banner), nunca a estrutura do
documento. `xml.etree.ElementTree` é adequado aqui; não é o caso de uso que `defusedxml`
existe para resolver (XML de terceiro não confiável).
"""

from __future__ import annotations

from dataclasses import dataclass
from xml.etree import ElementTree

from vulnai_discovery.errors import ParseError

DEFAULT_TIMEOUT = 300.0


@dataclass(frozen=True, slots=True)
class DiscoveredPort:
    port: int
    protocol: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None


@dataclass(frozen=True, slots=True)
class HostScanResult:
    address: str | None
    hostnames: tuple[str, ...]
    ports: tuple[DiscoveredPort, ...]


def build_command(
    target: str, *, ports: str = "top-1000", service_detection: bool = True
) -> list[str]:
    """Monta o comando nmap.

    `ports`: `"top-1000"` usa o padrão do nmap (não passa `-p`); `"all"` vira `-p-`;
    qualquer outro valor é passado literalmente a `-p` (ex.: `"80,443"`, `"1-1024"`).
    """
    command = ["nmap", "-oX", "-", "-Pn"]
    if service_detection:
        command.append("-sV")
    if ports == "all":
        command.append("-p-")
    elif ports != "top-1000":
        command.extend(["-p", ports])
    command.append(target)
    return command


def parse_xml(xml_text: str) -> list[HostScanResult]:
    """Extrai hosts com status `up` e portas com estado `open`.

    Portas fechadas/filtradas não viram `Service`: a etapa de descoberta registra
    superfície de ataque real, não a varredura inteira.
    """
    if not xml_text.strip():
        raise ParseError("saída do nmap está vazia")

    try:
        root = ElementTree.fromstring(xml_text)  # noqa: S314 - ver docstring do módulo
    except ElementTree.ParseError as exc:
        raise ParseError(f"XML do nmap inválido: {exc}") from exc

    hosts: list[HostScanResult] = []
    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue

        address = _first_address(host_el)
        hostnames = tuple(
            name
            for hn in host_el.findall("hostnames/hostname")
            if (name := hn.get("name"))
        )
        ports = tuple(_parse_port(port_el) for port_el in host_el.findall("ports/port"))
        ports = tuple(p for p in ports if p is not None)

        hosts.append(HostScanResult(address=address, hostnames=hostnames, ports=ports))

    return hosts


def _first_address(host_el: ElementTree.Element) -> str | None:
    """Prefere IPv4; usa IPv6 só se for o único endereço reportado."""
    addresses = host_el.findall("address")
    for addr in addresses:
        if addr.get("addrtype") == "ipv4":
            return addr.get("addr")
    for addr in addresses:
        if addr.get("addrtype") == "ipv6":
            return addr.get("addr")
    return None


def _parse_port(port_el: ElementTree.Element) -> DiscoveredPort | None:
    state = port_el.find("state")
    if state is None or state.get("state") != "open":
        return None

    portid = port_el.get("portid")
    protocol = port_el.get("protocol")
    if portid is None or protocol is None:
        return None

    service_el = port_el.find("service")
    service_name = product = version = cpe = None
    if service_el is not None:
        service_name = service_el.get("name")
        product = service_el.get("product")
        version = service_el.get("version")
        cpe_el = service_el.find("cpe")
        cpe = cpe_el.text.strip() if cpe_el is not None and cpe_el.text else None

    return DiscoveredPort(
        port=int(portid),
        protocol=protocol,
        service_name=service_name,
        product=product,
        version=version,
        cpe=cpe,
    )
