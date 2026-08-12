"""O gate. Nenhum módulo que toca ativo de cliente roda sem passar por aqui.

Ordem das checagens (a primeira que falhar nega e audita):

    1. token válido (assinatura, expiração, revogação)
    2. engagement existe e o tenant do token bate com o dela
    3. engagement ativa e dentro da janela contratada
    4. digest do escopo confere com o do token (sem drift contratual)
    5. alvo normalizável
    6. política de segurança da plataforma
    7. alvo dentro do escopo
    8. classe de ação dentro do teto efetivo
    9. opt-in intrusivo + aprovação humana, quando aplicável
    10. limite de intensidade

Rate limit é a **última** checagem de propósito: um pedido que já vai ser negado não
deve consumir a cota de um alvo legítimo.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from vulnai_shared.audit import AuditLog
from vulnai_shared.clock import Clock, utcnow
from vulnai_shared.enums import ActionClass, AuditEventType, Decision, EngagementStatus
from vulnai_shared.errors import (
    ActionNotAuthorizedError,
    AuthorizationError,
    EngagementStateError,
    EngagementWindowError,
    HumanApprovalRequiredError,
    IntrusiveActionNotAuthorizedError,
    InvalidTargetError,
    OutOfScopeError,
    RateLimitExceededError,
    SafetyPolicyError,
    ScopeDriftError,
    ScopeTokenError,
    TenantMismatchError,
)
from vulnai_shared.models import Engagement, ScopeRule
from vulnai_shared.targets import Target, parse_target
from vulnai_authorization.policy import DEFAULT_SAFETY_POLICY, SafetyPolicy
from vulnai_authorization.ratelimit import TokenBucketLimiter
from vulnai_authorization.repository import (
    ApprovalRepository,
    EngagementRepository,
    InMemoryApprovalRepository,
    InMemoryEngagementRepository,
)
from vulnai_authorization.scope import ScopeMatch, evaluate_scope
from vulnai_authorization.tokens import DEFAULT_TTL, ScopeToken, ScopeTokenSigner


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """Resultado de uma decisão do gate — sempre auditado, permitido ou não."""

    decision: Decision
    target: Target | None
    action: ActionClass
    reason: str
    client_id: str | None = None
    engagement_id: str | None = None
    token_jti: str | None = None
    matched_rule: ScopeRule | None = None
    #: Teto efetivo, já cruzado entre plataforma, engagement, token e regra.
    effective_max_action: ActionClass | None = None
    error_code: str | None = None
    audit_event_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    #: Exceção original da negação. `authorize` a relança preservando o tipo exato —
    #: reconstruí-la a partir do `error_code` degradaria subclasses (ex.: token expirado
    #: viraria "token inválido") e esconderia do chamador o que de fato aconteceu.
    error: AuthorizationError | None = None

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    def __bool__(self) -> bool:
        return self.allowed


class AuthorizationService:
    """Serviço de autorização e escopo (etapa `01_authorization` do pipeline)."""

    def __init__(
        self,
        *,
        signer: ScopeTokenSigner,
        audit_log: AuditLog,
        engagements: EngagementRepository | None = None,
        approvals: ApprovalRepository | None = None,
        limiter: TokenBucketLimiter | None = None,
        policy: SafetyPolicy = DEFAULT_SAFETY_POLICY,
        clock: Clock = utcnow,
    ) -> None:
        self._signer = signer
        self._audit = audit_log
        self._engagements = engagements or InMemoryEngagementRepository()
        self._approvals = approvals or InMemoryApprovalRepository()
        self._limiter = limiter or TokenBucketLimiter(clock=clock)
        self._policy = policy
        self._clock = clock

    # ------------------------------------------------------------------ emissão
    def issue_scope_token(
        self,
        engagement_id: str,
        *,
        operator: str,
        purpose: str,
        max_action: ActionClass = ActionClass.PASSIVE,
        ttl: timedelta = DEFAULT_TTL,
        expected_client_id: str | None = None,
    ) -> str:
        """Emite um `authorized_scope_token` para uma engagement aberta.

        `max_action` é `PASSIVE` por padrão: quem precisa de mais tem que pedir mais,
        explicitamente, e isso fica registrado no token e na auditoria.

        `expected_client_id` deve ser informado por todo chamador que já tenha um tenant
        em contexto (o backoffice sempre tem). Sem ele, conhecer o id de uma engagement
        alheia bastaria para receber um token válido para o cliente errado.
        """
        engagement = self._engagements.get(engagement_id)
        if engagement is None:
            self._deny_audit(
                actor=operator,
                reason=f"engagement {engagement_id} inexistente",
                engagement_id=engagement_id,
                error_code="engagement_not_found",
            )
            raise EngagementStateError(f"engagement {engagement_id} inexistente")

        if expected_client_id is not None and engagement.client_id != expected_client_id:
            self._deny_audit(
                actor=operator,
                reason="tentativa de emitir token para engagement de outro cliente",
                client_id=expected_client_id,
                engagement_id=engagement_id,
                error_code="tenant_mismatch",
            )
            raise TenantMismatchError(
                f"engagement {engagement_id} não pertence ao cliente {expected_client_id}"
            )

        now = self._clock()
        if engagement.status is not EngagementStatus.ACTIVE:
            self._deny_audit(
                actor=operator,
                reason=f"engagement em status {engagement.status.value}",
                client_id=engagement.client_id,
                engagement_id=engagement_id,
                error_code="engagement_not_active",
            )
            raise EngagementStateError(
                f"engagement {engagement_id} não está ativa ({engagement.status.value})"
            )
        if not engagement.window.contains(now):
            self._deny_audit(
                actor=operator,
                reason="fora da janela de autorização contratada",
                client_id=engagement.client_id,
                engagement_id=engagement_id,
                error_code="outside_window",
            )
            raise EngagementWindowError(
                f"agora ({now.isoformat()}) está fora da janela "
                f"{engagement.window.starts_at.isoformat()} .. "
                f"{engagement.window.ends_at.isoformat()}"
            )

        granted = _min_action(max_action, engagement.max_action, self._policy.platform_max_action)
        if granted is not max_action:
            raise ActionNotAuthorizedError(
                f"engagement/plataforma não permitem {max_action.value}; "
                f"teto disponível é {granted.value}"
            )

        raw, token = self._signer.issue(
            client_id=engagement.client_id,
            engagement_id=engagement.id,
            scope_digest=engagement.scope.digest(),
            scope_version=engagement.scope.version,
            operator=operator,
            max_action=granted,
            purpose=purpose,
            ttl=ttl,
            not_after=engagement.window.ends_at,
        )
        self._audit.record(
            AuditEventType.TOKEN_ISSUED,
            actor=operator,
            outcome="issued",
            client_id=engagement.client_id,
            engagement_id=engagement.id,
            details={
                "jti": token.jti,
                "max_action": granted.value,
                "purpose": purpose,
                "expires_at": token.expires_at.isoformat(),
                "scope_digest": token.scope_digest,
            },
        )
        return raw

    def revoke_scope_token(self, jti: str, *, actor: str, reason: str) -> None:
        """Parada de emergência: invalida um token já emitido."""
        self._signer.revoke(jti)
        self._audit.record(
            AuditEventType.TOKEN_REVOKED,
            actor=actor,
            outcome="revoked",
            details={"jti": jti, "reason": reason},
        )

    # ---------------------------------------------------------------- decisão
    def check(
        self,
        raw_token: str,
        raw_target: str,
        action: ActionClass = ActionClass.PASSIVE,
        *,
        actor: str | None = None,
        consume_quota: bool = True,
    ) -> AuthorizationDecision:
        """Avalia sem levantar exceção. Toda chamada gera evento de auditoria."""
        context = _DecisionContext(actor=actor)
        try:
            return self._evaluate(raw_token, raw_target, action, consume_quota, context)
        except AuthorizationError as exc:
            return self._denied_decision(exc, raw_target, action, context)

    def authorize(
        self,
        raw_token: str,
        raw_target: str,
        action: ActionClass = ActionClass.PASSIVE,
        *,
        actor: str | None = None,
        consume_quota: bool = True,
    ) -> AuthorizationDecision:
        """Autoriza ou levanta `AuthorizationError`. Caminho padrão dos scanners."""
        decision = self.check(
            raw_token, raw_target, action, actor=actor, consume_quota=consume_quota
        )
        if not decision.allowed:
            raise decision.error or OutOfScopeError(decision.reason)
        return decision

    # --------------------------------------------------------------- interno
    def _evaluate(
        self,
        raw_token: str,
        raw_target: str,
        action: ActionClass,
        consume_quota: bool,
        context: _DecisionContext,
    ) -> AuthorizationDecision:
        now = self._clock()

        # 1. token
        token = self._signer.verify(raw_token)
        context.absorb_token(token)
        who = context.actor or token.operator

        # 2. engagement + tenant
        engagement = self._engagements.get(token.engagement_id)
        if engagement is None:
            raise EngagementStateError(f"engagement {token.engagement_id} inexistente")
        if engagement.client_id != token.client_id:
            raise TenantMismatchError(
                f"token emitido para o cliente {token.client_id}, "
                f"engagement pertence a {engagement.client_id}"
            )

        # 3. estado e janela
        if engagement.status is not EngagementStatus.ACTIVE:
            raise EngagementStateError(
                f"engagement {engagement.id} não está ativa ({engagement.status.value})"
            )
        if not engagement.window.contains(now):
            raise EngagementWindowError(
                f"execução em {now.isoformat()} está fora da janela contratada"
            )

        # 4. drift de escopo
        if engagement.scope.digest() != token.scope_digest:
            raise ScopeDriftError(
                "escopo da engagement mudou desde a emissão do token; emita um novo token"
            )

        # 5. alvo
        target = parse_target(raw_target)

        # 6. política da plataforma
        self._policy.check(target)

        # 7. escopo
        match = evaluate_scope(engagement.scope, target)
        if not match.in_scope:
            raise OutOfScopeError(f"{target.value}: {match.reason}")

        # 8. teto de intensidade
        ceiling = self._effective_ceiling(engagement, token, match)
        if not ceiling.dominates(action):
            raise ActionNotAuthorizedError(
                f"ação {action.value} excede o teto autorizado ({ceiling.value}) "
                f"para {target.value}"
            )

        # 9. intrusivo: opt-in contratual + aprovação humana
        if action is ActionClass.INTRUSIVE:
            self._check_intrusive(engagement, target, now)

        # 10. intensidade
        if consume_quota and not self._limiter.acquire(engagement.id, target.value, engagement.limits):
            wait = self._limiter.retry_after(engagement.id, target.value, engagement.limits)
            raise RateLimitExceededError(
                f"limite de intensidade excedido para {target.value}; "
                f"tente novamente em {wait:.2f}s"
            )

        event = self._audit.record(
            AuditEventType.AUTHORIZATION_ALLOWED,
            actor=who,
            outcome=Decision.ALLOW.value,
            client_id=engagement.client_id,
            engagement_id=engagement.id,
            target=target.value,
            details={
                "action": action.value,
                "jti": token.jti,
                "matched_rule": str(match.matched_rule) if match.matched_rule else None,
                "effective_max_action": ceiling.value,
                "target_kind": target.kind.value,
            },
        )
        return AuthorizationDecision(
            decision=Decision.ALLOW,
            target=target,
            action=action,
            reason=match.reason,
            client_id=engagement.client_id,
            engagement_id=engagement.id,
            token_jti=token.jti,
            matched_rule=match.matched_rule,
            effective_max_action=ceiling,
            audit_event_id=event.id,
        )

    def _effective_ceiling(
        self, engagement: Engagement, token: ScopeToken, match: ScopeMatch
    ) -> ActionClass:
        """Menor teto entre plataforma, engagement, token e regra de escopo."""
        candidates = [
            self._policy.platform_max_action,
            engagement.max_action,
            token.max_action,
        ]
        if match.max_action is not None:
            candidates.append(match.max_action)
        return _min_action(*candidates)

    def _check_intrusive(self, engagement: Engagement, target: Target, now: datetime) -> None:
        optin = engagement.intrusive_authorization
        if optin is None:
            raise IntrusiveActionNotAuthorizedError(
                f"verificação intrusiva em {target.value} exige opt-in explícito "
                "registrado na engagement"
            )
        if not optin.window.contains(now):
            raise IntrusiveActionNotAuthorizedError(
                "janela do opt-in intrusivo não está aberta neste momento"
            )
        if optin.limited_to and target.value not in optin.limited_to:
            raise IntrusiveActionNotAuthorizedError(
                f"{target.value} não está na lista de alvos do opt-in intrusivo"
            )
        if self._policy.require_human_approval_for_intrusive:
            approval = self._approvals.find(
                engagement.id, target.value, ActionClass.INTRUSIVE, now
            )
            if approval is None:
                raise HumanApprovalRequiredError(
                    f"ação intrusiva em {target.value} exige aprovação humana vigente"
                )

    # ------------------------------------------------------------- auditoria
    def _denied_decision(
        self,
        exc: AuthorizationError,
        raw_target: str,
        action: ActionClass,
        context: _DecisionContext,
    ) -> AuthorizationDecision:
        code = error_code_for(exc)
        event = self._deny_audit(
            actor=context.actor or context.operator or "unknown",
            reason=str(exc),
            client_id=context.client_id,
            engagement_id=context.engagement_id,
            target=raw_target,
            error_code=code,
            details={"action": action.value, "jti": context.jti},
        )
        return AuthorizationDecision(
            decision=Decision.DENY,
            target=None,
            action=action,
            reason=str(exc),
            client_id=context.client_id,
            engagement_id=context.engagement_id,
            token_jti=context.jti,
            error_code=code,
            audit_event_id=event.id,
            error=exc,
        )

    def _deny_audit(
        self,
        *,
        actor: str,
        reason: str,
        client_id: str | None = None,
        engagement_id: str | None = None,
        target: str | None = None,
        error_code: str = "denied",
        details: dict[str, Any] | None = None,
    ):
        payload = {"error_code": error_code, "reason": reason}
        payload.update(details or {})
        return self._audit.record(
            AuditEventType.AUTHORIZATION_DENIED,
            actor=actor,
            outcome=Decision.DENY.value,
            client_id=client_id,
            engagement_id=engagement_id,
            # Alvo negado é registrado como veio, sem normalizar: o valor bruto é a prova.
            target=target,
            details=payload,
        )


def _min_action(*actions: ActionClass) -> ActionClass:
    return min(actions, key=lambda action: action.level)


@dataclass
class _DecisionContext:
    """Contexto acumulado durante a avaliação, para auditar bem também as negações.

    Só é preenchido depois que o token passou pela verificação de assinatura — dados de
    um token não verificado não entram na trilha como se fossem fato.
    """

    actor: str | None = None
    client_id: str | None = None
    engagement_id: str | None = None
    jti: str | None = None
    operator: str | None = None

    def absorb_token(self, token: ScopeToken) -> None:
        self.client_id = token.client_id
        self.engagement_id = token.engagement_id
        self.jti = token.jti
        self.operator = token.operator


#: Ordem importa: o primeiro tipo que casar por `isinstance` vence, então as subclasses
#: mais específicas vêm antes das bases.
_ERROR_CODES: tuple[tuple[type[AuthorizationError], str], ...] = (
    (ScopeDriftError, "scope_drift"),
    (ScopeTokenError, "invalid_token"),
    (TenantMismatchError, "tenant_mismatch"),
    (EngagementStateError, "engagement_not_active"),
    (EngagementWindowError, "outside_window"),
    (InvalidTargetError, "invalid_target"),
    (SafetyPolicyError, "blocked_by_policy"),
    (OutOfScopeError, "out_of_scope"),
    (HumanApprovalRequiredError, "human_approval_required"),
    (IntrusiveActionNotAuthorizedError, "intrusive_not_authorized"),
    (ActionNotAuthorizedError, "action_not_authorized"),
    (RateLimitExceededError, "rate_limited"),
)

def error_code_for(exc: AuthorizationError) -> str:
    """Código estável do motivo da negação — usado na auditoria e na API."""
    for error_type, code in _ERROR_CODES:
        if isinstance(exc, error_type):
            return code
    return "denied"
