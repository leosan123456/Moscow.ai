"""Motor de correspondência de escopo.

Duas regras estruturais, ambas conservadoras por decisão:

1. **Exclusão vence inclusão.** Sempre, independentemente de ordem ou especificidade.
2. **Sem inferência entre tipos.** Um hostname não casa com uma regra de CIDR e um IP não
   casa com uma regra de domínio. Fazer a ponte exigiria resolver DNS no momento da
   decisão, e aí quem controla o registro DNS controla o escopo.

Quando várias regras de inclusão casam, o teto de intensidade adotado é o **mais
restritivo** entre elas.
"""

from __future__ import annotations

from dataclasses import dataclass

from vulnai_shared.enums import ActionClass, ScopeRuleKind, TargetKind
from vulnai_shared.models import Scope, ScopeRule
from vulnai_shared.targets import Target, normalize_network


@dataclass(frozen=True, slots=True)
class ScopeMatch:
    """Resultado da avaliação de um alvo contra o escopo."""

    in_scope: bool
    reason: str
    matched_rule: ScopeRule | None = None
    #: Teto de intensidade imposto pelas regras que casaram (`None` = herda a engagement).
    max_action: ActionClass | None = None


def evaluate_scope(scope: Scope, target: Target) -> ScopeMatch:
    """Decide se `target` pertence a `scope`."""
    for rule in scope.excludes:
        if rule_matches(rule, target):
            return ScopeMatch(
                in_scope=False,
                reason=f"alvo casa com regra de exclusão {rule}",
                matched_rule=rule,
            )

    matched = [rule for rule in scope.includes if rule_matches(rule, target)]
    if not matched:
        return ScopeMatch(
            in_scope=False,
            reason="alvo não casa com nenhuma regra de inclusão do escopo contratado",
        )

    ceiling = _most_restrictive_action(matched)
    best = _most_specific(matched)
    return ScopeMatch(
        in_scope=True,
        reason=f"alvo autorizado pela regra {best}",
        matched_rule=best,
        max_action=ceiling,
    )


def rule_matches(rule: ScopeRule, target: Target) -> bool:
    """Correspondência entre uma regra e um alvo já normalizado."""
    match rule.kind:
        case ScopeRuleKind.CIDR:
            return target.ip is not None and target.ip in normalize_network(rule.value)

        case ScopeRuleKind.IP:
            return target.ip is not None and str(target.ip) == rule.value

        case ScopeRuleKind.DOMAIN:
            host = _hostname_of(target)
            # `endswith` sozinho casaria `evil-example.com` com `example.com`;
            # o ponto explícito garante fronteira de rótulo.
            return host is not None and (host == rule.value or host.endswith("." + rule.value))

        case ScopeRuleKind.HOSTNAME:
            return _hostname_of(target) == rule.value

        case ScopeRuleKind.URL_PREFIX:
            return _url_prefix_matches(rule.value, target)

        case ScopeRuleKind.CLOUD_ACCOUNT:
            if target.cloud_provider is None or target.cloud_account is None:
                return False
            return f"{target.cloud_provider}:{target.cloud_account}" == rule.value

    return False


def _hostname_of(target: Target) -> str | None:
    """Hostname do alvo, apenas quando ele é de fato um nome (nunca um IP literal)."""
    if target.ip is not None:
        return None
    if target.kind not in (TargetKind.HOSTNAME, TargetKind.URL):
        return None
    return target.host


def _url_prefix_matches(rule_value: str, target: Target) -> bool:
    if target.kind is not TargetKind.URL or target.scheme is None:
        return False

    rule_scheme, _, remainder = rule_value.partition("://")
    slash = remainder.find("/")
    rule_authority = remainder if slash == -1 else remainder[:slash]
    rule_path = "/" if slash == -1 else remainder[slash:]

    target_authority = target.value.removeprefix(f"{target.scheme}://").split("/", 1)[0]
    if target.scheme != rule_scheme or target_authority != rule_authority:
        return False

    if rule_path == "/":
        return True
    # `/admin` cobre `/admin` e `/admin/...`, mas não `/administrador`.
    return target.path == rule_path or target.path.startswith(rule_path + "/")


def _most_restrictive_action(rules: list[ScopeRule]) -> ActionClass | None:
    ceilings = [rule.max_action for rule in rules if rule.max_action is not None]
    if not ceilings:
        return None
    return min(ceilings, key=lambda action: action.level)


def _most_specific(rules: list[ScopeRule]) -> ScopeRule:
    """Regra mais específica entre as que casaram — usada só para explicar a decisão."""
    specificity = {
        ScopeRuleKind.URL_PREFIX: 5,
        ScopeRuleKind.HOSTNAME: 4,
        ScopeRuleKind.IP: 4,
        ScopeRuleKind.CLOUD_ACCOUNT: 3,
        ScopeRuleKind.DOMAIN: 2,
        ScopeRuleKind.CIDR: 1,
    }
    return max(rules, key=lambda rule: (specificity.get(rule.kind, 0), len(rule.value)))
