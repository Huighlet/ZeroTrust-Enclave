"""
Tests for ZeroTrustGateway end-to-end attestation, credential issuance,
microsegmentation authorization, and chained audit ledger.
"""

import hashlib
import pytest
from zerotrust.gateway import ZeroTrustGateway
from zerotrust.policy import PolicyRule
from zerotrust.types import (
    AccessDecision,
    AccessDeniedError,
    SpiffeID,
    SVIDRevokedError,
    WorkloadProfile,
)


@pytest.fixture
def gateway() -> ZeroTrustGateway:
    gw = ZeroTrustGateway(trust_domain="prod.mesh")

    # Binary payload and digest
    bin_bytes = b"BINARY_IMAGE_PAYLOAD_ACCOUNT_SERVICE"
    digest = hashlib.sha256(bin_bytes).hexdigest()

    # Register Workload
    profile = WorkloadProfile(
        profile_id="account-svc",
        spiffe_id=SpiffeID.parse("spiffe://prod.mesh/ns/banking/service/account"),
        expected_binary_sha256=digest,
        expected_image_path="/usr/local/bin/account-svc",
        environment="prod",
    )
    gw.register_workload(profile)

    # Register Microsegmentation Rule
    gw.add_policy_rule(
        PolicyRule(
            rule_id="allow-account-to-ledger",
            source_pattern="spiffe://prod.mesh/ns/banking/service/*",
            target_pattern="spiffe://prod.mesh/ns/ledger/service/core",
            allowed_actions={"TRANSFER"},
            effect=AccessDecision.ALLOW,
        )
    )
    return gw


def test_gateway_full_attestation_and_authorization(gateway):
    bin_bytes = b"BINARY_IMAGE_PAYLOAD_ACCOUNT_SERVICE"

    # Step 1: Authenticate and get SVID
    svid = gateway.authenticate_workload(
        candidate_bytes=bin_bytes,
        profile_id="account-svc",
        environment="prod",
    )
    assert svid.spiffe_id.uri == "spiffe://prod.mesh/ns/banking/service/account"

    # Step 2: Authorize legitimate cross-service call
    target = SpiffeID.parse("spiffe://prod.mesh/ns/ledger/service/core")
    decision = gateway.authorize_request(
        client_svid=svid,
        target_spiffe_id=target,
        action="TRANSFER",
    )
    assert decision == AccessDecision.ALLOW

    # Verify audit chain integrity
    assert gateway.verify_audit_chain_integrity() is True
    assert len(gateway.audit_chain) >= 2


def test_gateway_unauthorized_target_rejected(gateway):
    bin_bytes = b"BINARY_IMAGE_PAYLOAD_ACCOUNT_SERVICE"
    svid = gateway.authenticate_workload(
        candidate_bytes=bin_bytes,
        profile_id="account-svc",
        environment="prod",
    )

    unauthorized_target = SpiffeID.parse("spiffe://prod.mesh/ns/secret/service/vault")
    with pytest.raises(AccessDeniedError):
        gateway.authorize_request(
            client_svid=svid,
            target_spiffe_id=unauthorized_target,
            action="READ",
        )


def test_gateway_revocation_denies_authorization(gateway):
    bin_bytes = b"BINARY_IMAGE_PAYLOAD_ACCOUNT_SERVICE"
    svid = gateway.authenticate_workload(
        candidate_bytes=bin_bytes,
        profile_id="account-svc",
        environment="prod",
    )

    # Revoke token
    gateway.revoke_svid(svid.serial_number)

    target = SpiffeID.parse("spiffe://prod.mesh/ns/ledger/service/core")
    with pytest.raises(SVIDRevokedError):
        gateway.authorize_request(
            client_svid=svid,
            target_spiffe_id=target,
            action="TRANSFER",
        )
