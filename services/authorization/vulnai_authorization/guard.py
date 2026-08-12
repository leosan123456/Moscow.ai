"""Fachada que os módulos de varredura usam.

`ScopeGuard` é o único caminho pelo qual discovery/collection/validation devem tocar um
ativo. Ele obriga o par autorização + auditoria a acontecer junto: `touch()` autoriza
antes de entregar o alvo e registra o resultado depois, inclusive quando a operação
falha. Chamar o scanner sem passar por aqui é o bug que a revisão de código procura.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass

from vulnai_shared.audit import AuditLog
from vulnai_shared.enums import ActionClass, AuditEventType
from vulnai_shared.errors import AuthorizationError
from vulnai_shared.targets import Target
from vulnai_authorization.service import AuthorizationDecision, AuthorizationService


@dataclass(frozen=True, slots=True)
class TargetRejection:
    """Alvo descartado, com o motivo — vai para o relatório de cobertura da execução."""

    raw_target: str
    reason: str
    error_code: str | None


class ScopeGuard:
    """Vincula um token de escopo a um operador e a um `AuthorizationService`."""

    def __init__(
        self,
        service: AuthorizationService,
        raw_token: str,
        *,
        actor: str,
        audit_log: AuditLog | None = None,
    ) -> None:
        self._service = service
        self._token = raw_token
        self._actor = actor
        self._audit = audit_log

    def authorize(self, raw_target: str, action: ActionClass) -> AuthorizationDecision:
        """Autoriza um alvo ou levanta `AuthorizationError`."""
        return self._service.authorize(self._token, raw_target, action, actor=self._actor)

    def is_allowed(self, raw_target: str, action: ActionClass) -> bool:
        """Consulta sem consumir cota — para pré-filtrar listas grandes de candidatos."""
        return self._service.check(
            self._token, raw_target, action, actor=self._actor, consume_quota=False
        ).allowed

    def partition(
        self, raw_targets: Sequence[str], action: ActionClass
    ) -> tuple[list[str], list[TargetRejection]]:
        """Separa candidatos em autorizados e rejeitados, sem consumir cota.

        Descobertas geram muito candidato fora de escopo (subdomínio de terceiro, IP de
        CDN). Filtrar antes evita que o rate limit seja gasto com alvo que seria negado.

        A lista autorizada sai deduplicada **pela forma normalizada**: as fontes de
        descoberta costumam entregar o mesmo host em grafias diferentes, e devolver os
        dois dobraria a carga sobre o ativo do cliente. A ordem de primeira aparição é
        preservada. Rejeições não são deduplicadas — cada tentativa é registro próprio.
        """
        allowed: list[str] = []
        seen: set[str] = set()
        rejected: list[TargetRejection] = []
        for raw in raw_targets:
            decision = self._service.check(
                self._token, raw, action, actor=self._actor, consume_quota=False
            )
            if decision.allowed and decision.target is not None:
                if decision.target.value not in seen:
                    seen.add(decision.target.value)
                    allowed.append(decision.target.value)
            else:
                rejected.append(
                    TargetRejection(
                        raw_target=raw, reason=decision.reason, error_code=decision.error_code
                    )
                )
        return allowed, rejected

    @contextmanager
    def touch(self, raw_target: str, action: ActionClass, *, tool: str) -> Iterator[Target]:
        """Autoriza, entrega o alvo normalizado e audita o desfecho.

        Uso:
            with guard.touch("api.cliente.com", ActionClass.ACTIVE_NON_INTRUSIVE,
                             tool="nmap") as target:
                run_scan(target)
        """
        decision = self.authorize(raw_target, action)
        assert decision.target is not None  # garantido por `authorize`
        target = decision.target
        outcome = "completed"
        error: str | None = None
        try:
            yield target
        except AuthorizationError:
            raise
        except Exception as exc:
            outcome, error = "failed", f"{type(exc).__name__}: {exc}"
            raise
        finally:
            audit = self._audit
            if audit is not None:
                audit.record(
                    AuditEventType.ASSET_TOUCHED,
                    actor=self._actor,
                    outcome=outcome,
                    client_id=decision.client_id,
                    engagement_id=decision.engagement_id,
                    target=target.value,
                    details={
                        "action": action.value,
                        "tool": tool,
                        "jti": decision.token_jti,
                        "error": error,
                    },
                )
