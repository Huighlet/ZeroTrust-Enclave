"""
ZeroTrust-Enclave: Microsegmentation Policy Engine.
Enforces Attribute-Based Access Control (ABAC) and SPIFFE-based Default Deny rules.
"""

from __future__ import annotations

import dataclasses
import fnmatch
from typing import Dict, List, Optional, Set

from zerotrust.types import (
    AccessDecision,
    AccessDeniedError,
    AuthContext,
    SpiffeID,
)


@dataclasses.dataclass(slots=True, frozen=True)
class PolicyRule:
    """
    Microsegmentation policy rule definition.
    Evaluates source/target SPIFFE URIs, allowed actions, and contextual attributes.
    """
    rule_id: str
    source_pattern: str  # e.g., "spiffe://prod.internal/ns/finance/*"
    target_pattern: str  # e.g., "spiffe://prod.internal/ns/ledger/service/core"
    allowed_actions: Set[str] = dataclasses.field(default_factory=lambda: {"*"})
    required_attributes: Dict[str, str] = dataclasses.field(default_factory=dict)
    effect: AccessDecision = AccessDecision.ALLOW
    description: str = ""

    def matches_source(self, spiffe_id: SpiffeID) -> bool:
        """Check if candidate source SPIFFE URI matches the source pattern."""
        if self.source_pattern == "*":
            return True
        return fnmatch.fnmatchcase(spiffe_id.uri, self.source_pattern)

    def matches_target(self, spiffe_id: SpiffeID) -> bool:
        """Check if candidate target SPIFFE URI matches the target pattern."""
        if self.target_pattern == "*":
            return True
        return fnmatch.fnmatchcase(spiffe_id.uri, self.target_pattern)

    def matches_action(self, action: str) -> bool:
        """Check if action is permitted under this rule."""
        if "*" in self.allowed_actions:
            return True
        return action.upper() in {a.upper() for a in self.allowed_actions}

    def matches_attributes(self, client_attributes: Dict[str, str]) -> bool:
        """Check if all required key-value attributes are satisfied."""
        for key, val in self.required_attributes.items():
            if client_attributes.get(key) != val:
                return False
        return True


class MicrosegmentationPolicyEngine:
    """
    Evaluates authorization requests across microsegmentation boundaries.
    Default Deny Invariant: Any traffic without an explicit matching ALLOW rule is rejected.
    """

    def __init__(self) -> None:
        self._rules: List[PolicyRule] = []

    def add_rule(self, rule: PolicyRule) -> None:
        """Append an authorization rule to the policy engine."""
        self._rules.append(rule)

    def clear_rules(self) -> None:
        """Clear all active rules."""
        self._rules.clear()

    @property
    def rules(self) -> List[PolicyRule]:
        return list(self._rules)

    def evaluate(self, context: AuthContext) -> tuple[AccessDecision, Optional[PolicyRule]]:
        """
        Evaluate an AuthContext against the active ruleset in priority order.
        Returns:
            Tuple of (AccessDecision, matched_rule or None)
        """
        for rule in self._rules:
            if not rule.matches_source(context.source_spiffe_id):
                continue
            if not rule.matches_target(context.target_spiffe_id):
                continue
            if not rule.matches_action(context.action):
                continue
            if not rule.matches_attributes(context.client_attributes):
                continue

            # First matching rule determines the outcome
            return rule.effect, rule

        # Default Deny Invariant
        return AccessDecision.DENY, None

    def enforce(self, context: AuthContext) -> None:
        """
        Enforce policy decision, raising AccessDeniedError if not allowed.
        """
        decision, matched_rule = self.evaluate(context)
        if decision != AccessDecision.ALLOW:
            rule_info = f" (matched deny rule '{matched_rule.rule_id}')" if matched_rule else " (default deny: no rule matched)"
            raise AccessDeniedError(
                f"Microsegmentation access denied from '{context.source_spiffe_id}' "
                f"to '{context.target_spiffe_id}' for action '{context.action}'{rule_info}."
            )
