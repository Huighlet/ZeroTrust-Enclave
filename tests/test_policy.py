"""
Tests for Microsegmentation ABAC Policy Engine & Default Deny Invariant.
"""

import pytest
from zerotrust.policy import MicrosegmentationPolicyEngine, PolicyRule
from zerotrust.types import AccessDecision, AccessDeniedError, AuthContext, SpiffeID


@pytest.fixture
def policy_engine() -> MicrosegmentationPolicyEngine:
    eng = MicrosegmentationPolicyEngine()
    eng.add_rule(
        PolicyRule(
            rule_id="frontend-to-backend-get",
            source_pattern="spiffe://cluster.local/ns/frontend/*",
            target_pattern="spiffe://cluster.local/ns/backend/service/api",
            allowed_actions={"GET", "POST"},
            required_attributes={"env": "prod"},
            effect=AccessDecision.ALLOW,
        )
    )
    return eng


def test_default_deny_when_no_rules_match(policy_engine):
    unmatched_ctx = AuthContext(
        source_spiffe_id=SpiffeID.parse("spiffe://cluster.local/ns/unknown/app"),
        target_spiffe_id=SpiffeID.parse("spiffe://cluster.local/ns/backend/service/api"),
        action="GET",
        client_attributes={"env": "prod"},
    )
    decision, rule = policy_engine.evaluate(unmatched_ctx)
    assert decision == AccessDecision.DENY
    assert rule is None

    with pytest.raises(AccessDeniedError, match="default deny: no rule matched"):
        policy_engine.enforce(unmatched_ctx)


def test_rule_matching_allow(policy_engine):
    ctx = AuthContext(
        source_spiffe_id=SpiffeID.parse("spiffe://cluster.local/ns/frontend/web-ui"),
        target_spiffe_id=SpiffeID.parse("spiffe://cluster.local/ns/backend/service/api"),
        action="GET",
        client_attributes={"env": "prod"},
    )
    decision, rule = policy_engine.evaluate(ctx)
    assert decision == AccessDecision.ALLOW
    assert rule.rule_id == "frontend-to-backend-get"
    # enforce should not raise
    policy_engine.enforce(ctx)


def test_action_restriction_enforced(policy_engine):
    ctx = AuthContext(
        source_spiffe_id=SpiffeID.parse("spiffe://cluster.local/ns/frontend/web-ui"),
        target_spiffe_id=SpiffeID.parse("spiffe://cluster.local/ns/backend/service/api"),
        action="DELETE",  # Not in {"GET", "POST"}
        client_attributes={"env": "prod"},
    )
    decision, rule = policy_engine.evaluate(ctx)
    assert decision == AccessDecision.DENY


def test_required_attributes_mismatch(policy_engine):
    ctx = AuthContext(
        source_spiffe_id=SpiffeID.parse("spiffe://cluster.local/ns/frontend/web-ui"),
        target_spiffe_id=SpiffeID.parse("spiffe://cluster.local/ns/backend/service/api"),
        action="GET",
        client_attributes={"env": "dev"},  # Required is "prod"
    )
    decision, rule = policy_engine.evaluate(ctx)
    assert decision == AccessDecision.DENY
