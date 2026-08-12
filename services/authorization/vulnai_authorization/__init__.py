"""Serviço de autorização e escopo — o gate da plataforma (etapa `01_authorization`).

Nenhuma etapa posterior do pipeline executa sem um `authorized_scope_token` válido
emitido e verificado aqui.
"""

from vulnai_authorization.guard import ScopeGuard, TargetRejection
from vulnai_authorization.policy import DEFAULT_SAFETY_POLICY, SafetyPolicy
from vulnai_authorization.ratelimit import TokenBucketLimiter
from vulnai_authorization.repository import (
    ApprovalRepository,
    EngagementRepository,
    HumanApproval,
    InMemoryApprovalRepository,
    InMemoryEngagementRepository,
)
from vulnai_authorization.scope import ScopeMatch, evaluate_scope, rule_matches
from vulnai_authorization.service import (
    AuthorizationDecision,
    AuthorizationService,
    error_code_for,
)
from vulnai_authorization.tokens import ScopeToken, ScopeTokenSigner, generate_secret

__all__ = [
    "DEFAULT_SAFETY_POLICY",
    "ApprovalRepository",
    "AuthorizationDecision",
    "AuthorizationService",
    "EngagementRepository",
    "HumanApproval",
    "InMemoryApprovalRepository",
    "InMemoryEngagementRepository",
    "SafetyPolicy",
    "ScopeGuard",
    "ScopeMatch",
    "ScopeToken",
    "ScopeTokenSigner",
    "TargetRejection",
    "TokenBucketLimiter",
    "error_code_for",
    "evaluate_scope",
    "generate_secret",
    "rule_matches",
]
