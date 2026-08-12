"""Normalização de alvos e de regras de escopo.

Camada crítica de segurança: toda comparação de escopo acontece sobre a **forma
normalizada**. Se a normalização for frouxa, o gate vira decoração — variações como
`EXAMPLE.com.`, `http://interno@evil.com`, `0177.0.0.1` ou IDN homógrafo são justamente
os vetores usados para arrastar um scanner para fora do escopo contratado.

Regra estrutural: **nada aqui resolve DNS**. Um hostname entra em escopo por regra de
domínio/host; um IP entra por regra de CIDR/IP. Resolver nome para IP durante a decisão
permitiria que um registro DNS controlado pelo alvo mudasse o escopo em runtime.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from vulnai_shared.enums import ScopeRuleKind, TargetKind
from vulnai_shared.errors import InvalidTargetError

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_MAX_RAW_LENGTH = 512
_HOSTNAME_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")
_CLOUD_RE = re.compile(r"^(aws|gcp|azure|oci):([a-z0-9][a-z0-9._-]{0,127})(/(?P<res>.+))?$")
_ALLOWED_SCHEMES = frozenset({"http", "https"})


@dataclass(frozen=True, slots=True)
class Target:
    """Alvo normalizado, pronto para comparação com o escopo."""

    raw: str
    kind: TargetKind
    #: Forma canônica — o que é persistido, auditado e comparado.
    value: str
    host: str | None = None
    ip: IPAddress | None = None
    port: int | None = None
    scheme: str | None = None
    path: str = "/"
    cloud_provider: str | None = None
    cloud_account: str | None = None
    cloud_resource: str | None = None

    def __str__(self) -> str:
        return self.value


# --------------------------------------------------------------------------------------
# Hostname
# --------------------------------------------------------------------------------------


def normalize_hostname(raw: str) -> str:
    """Normaliza um hostname: minúsculas, IDNA/punycode, sem ponto final.

    Rejeita qualquer coisa que não sobreviva à normalização em ASCII — um host com
    caractere Unicode residual é homógrafo em potencial e não pode ser comparado
    com segurança contra uma regra de contrato.
    """
    host = raw.strip().strip(".").lower()
    if not host:
        raise InvalidTargetError("hostname vazio")
    if len(host) > 253:
        raise InvalidTargetError(f"hostname excede 253 caracteres: {raw!r}")

    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise InvalidTargetError(f"hostname IDN inválido: {raw!r}") from exc

    if not _HOSTNAME_RE.match(host):
        raise InvalidTargetError(f"hostname inválido: {raw!r}")
    if host.rsplit(".", 1)[-1].isdigit():
        # TLD numérico não existe; normalmente é um IP malformado disfarçado de nome.
        raise InvalidTargetError(f"hostname com TLD numérico: {raw!r}")
    return host


def normalize_ip(raw: str) -> IPAddress:
    """Converte para objeto de IP, rejeitando formas ambíguas.

    `ipaddress` já recusa octal com zero à esquerda (`0177.0.0.1`) e inteiro puro
    (`2130706433`) — as duas formas clássicas de confundir um parser permissivo.
    """
    text = raw.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        return ipaddress.ip_address(text)
    except ValueError as exc:
        raise InvalidTargetError(f"endereço IP inválido: {raw!r}") from exc


def normalize_network(raw: str) -> IPNetwork:
    try:
        return ipaddress.ip_network(raw.strip(), strict=False)
    except ValueError as exc:
        raise InvalidTargetError(f"CIDR inválido: {raw!r}") from exc


# --------------------------------------------------------------------------------------
# Alvos
# --------------------------------------------------------------------------------------


def parse_target(raw: str) -> Target:
    """Interpreta uma string de alvo em uma das formas suportadas.

    Suporta: URL (`https://api.example.com/v1`), IP (`203.0.113.10`), hostname
    (`api.example.com`) e recurso de nuvem (`aws:123456789012/s3/bucket`).
    """
    if not isinstance(raw, str):
        raise InvalidTargetError(f"alvo deve ser string, recebido {type(raw)!r}")

    text = raw.strip()
    if not text:
        raise InvalidTargetError("alvo vazio")
    if len(text) > _MAX_RAW_LENGTH:
        raise InvalidTargetError(f"alvo excede {_MAX_RAW_LENGTH} caracteres")
    if any(ch.isspace() or ord(ch) < 0x20 for ch in text):
        raise InvalidTargetError(f"alvo contém espaço ou caractere de controle: {raw!r}")

    if "://" in text:
        return _parse_url(text)

    cloud = _CLOUD_RE.match(text.lower())
    if cloud:
        return _build_cloud_target(text, cloud)

    host_part, port = _split_host_port(text)

    try:
        ip = normalize_ip(host_part)
    except InvalidTargetError:
        ip = None

    if ip is not None:
        value = _format_host(ip, port)
        return Target(raw=raw, kind=TargetKind.IP, value=value, ip=ip, port=port, host=str(ip))

    host = normalize_hostname(host_part)
    return Target(
        raw=raw,
        kind=TargetKind.HOSTNAME,
        value=_format_host(host, port),
        host=host,
        port=port,
    )


def _parse_url(text: str) -> Target:
    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise InvalidTargetError(f"esquema de URL não suportado: {scheme!r}")
    if "@" in parts.netloc:
        # `http://api.cliente.com@evil.tld` aponta para evil.tld. Recusar é mais seguro
        # do que confiar que todo consumidor a jusante vá reparsear igual.
        raise InvalidTargetError("URL com userinfo não é aceita como alvo")
    if not parts.hostname:
        raise InvalidTargetError(f"URL sem host: {text!r}")

    try:
        port = parts.port
    except ValueError as exc:
        raise InvalidTargetError(f"porta inválida na URL: {text!r}") from exc
    if port is not None and not 1 <= port <= 65535:
        # `urlsplit` aceita porta 0; aqui ela é inválida como alvo.
        raise InvalidTargetError(f"porta fora do intervalo na URL: {text!r}")

    try:
        ip: IPAddress | None = normalize_ip(parts.hostname)
        host = str(ip)
    except InvalidTargetError:
        ip = None
        host = normalize_hostname(parts.hostname)

    path = parts.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    authority = _format_host(host, port)
    return Target(
        raw=text,
        kind=TargetKind.URL,
        value=f"{scheme}://{authority}{path}",
        host=host,
        ip=ip,
        port=port,
        scheme=scheme,
        path=path,
    )


def _build_cloud_target(raw: str, match: re.Match[str]) -> Target:
    provider, account = match.group(1), match.group(2)
    resource = match.group("res")
    if resource:
        value = f"{provider}:{account}/{resource}"
        kind = TargetKind.CLOUD_RESOURCE
    else:
        value = f"{provider}:{account}"
        kind = TargetKind.CLOUD_ACCOUNT
    return Target(
        raw=raw,
        kind=kind,
        value=value,
        cloud_provider=provider,
        cloud_account=account,
        cloud_resource=resource,
    )


def _split_host_port(text: str) -> tuple[str, int | None]:
    """Separa `host:porta`, respeitando IPv6 entre colchetes."""
    if text.startswith("["):
        closing = text.find("]")
        if closing == -1:
            raise InvalidTargetError(f"IPv6 sem colchete de fechamento: {text!r}")
        host = text[1 : closing]
        rest = text[closing + 1 :]
        if not rest:
            return host, None
        if not rest.startswith(":"):
            raise InvalidTargetError(f"alvo IPv6 malformado: {text!r}")
        return host, _parse_port(rest[1:], text)

    if text.count(":") == 1:
        host, _, port_text = text.partition(":")
        return host, _parse_port(port_text, text)

    # Mais de um ':' sem colchetes só pode ser IPv6 puro (sem porta).
    return text, None


def _parse_port(port_text: str, context: str) -> int:
    if not port_text.isdigit():
        raise InvalidTargetError(f"porta inválida em {context!r}")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise InvalidTargetError(f"porta fora do intervalo em {context!r}")
    return port


def _format_host(host: str | IPAddress, port: int | None) -> str:
    """Forma canônica do par host/porta.

    IPv6 só recebe colchetes quando há porta — sem eles `2001:db8::1:443` seria ambíguo.
    """
    rendered = str(host)
    if port is None:
        return rendered
    is_ipv6 = isinstance(host, ipaddress.IPv6Address) or (
        isinstance(host, str) and host.count(":") > 1
    )
    return f"[{rendered}]:{port}" if is_ipv6 else f"{rendered}:{port}"


# --------------------------------------------------------------------------------------
# Regras de escopo
# --------------------------------------------------------------------------------------


def normalize_rule_value(kind: ScopeRuleKind, value: str) -> str:
    """Normaliza o valor de uma regra na construção do `ScopeRule`."""
    text = value.strip()
    if not text:
        raise InvalidTargetError("regra de escopo com valor vazio")

    match kind:
        case ScopeRuleKind.CIDR:
            return str(normalize_network(text))
        case ScopeRuleKind.IP:
            return str(normalize_ip(text))
        case ScopeRuleKind.DOMAIN:
            # `*.example.com` e `.example.com` são apelidos de `example.com` como sufixo.
            stripped = text.lower().removeprefix("*.").removeprefix(".")
            return normalize_hostname(stripped)
        case ScopeRuleKind.HOSTNAME:
            return normalize_hostname(text)
        case ScopeRuleKind.URL_PREFIX:
            return _normalize_url_prefix(text)
        case ScopeRuleKind.CLOUD_ACCOUNT:
            match_ = _CLOUD_RE.match(text.lower())
            if not match_ or match_.group("res"):
                raise InvalidTargetError(f"conta de nuvem inválida: {value!r}")
            return f"{match_.group(1)}:{match_.group(2)}"

    raise InvalidTargetError(f"tipo de regra desconhecido: {kind!r}")


def _normalize_url_prefix(text: str) -> str:
    target = _parse_url(text if "://" in text else f"https://{text}")
    path = target.path
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    authority = _format_host(target.ip or target.host or "", target.port)
    return f"{target.scheme}://{authority}{path}"
