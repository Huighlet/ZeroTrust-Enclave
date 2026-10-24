"""
Tests for Ephemeral Certificate Authority (CA) & SVID Token Lifecycle.
"""

import time
import pytest
from zerotrust.ca import EphemeralCertificateAuthority
from zerotrust.types import (
    SpiffeID,
    SVIDExpiredError,
    SVIDRevokedError,
    ZeroTrustSecurityError,
)


@pytest.fixture
def ca() -> EphemeralCertificateAuthority:
    return EphemeralCertificateAuthority(trust_domain="enclave.local", default_ttl_seconds=10.0)


@pytest.fixture
def sample_spiffe() -> SpiffeID:
    return SpiffeID.parse("spiffe://enclave.local/ns/default/service/order-api")


def test_svid_issuance_and_verification(ca, sample_spiffe):
    token = ca.issue_svid(sample_spiffe, ttl_seconds=60.0)
    assert token.spiffe_id == sample_spiffe
    assert token.serial_number.startswith("svid-")
    assert ca.verify_svid(token) is True
    assert token.is_valid is True


def test_cross_trust_domain_issuance_rejected(ca):
    foreign_spiffe = SpiffeID.parse("spiffe://foreign.domain/service/api")
    with pytest.raises(ZeroTrustSecurityError, match="does not match CA trust domain"):
        ca.issue_svid(foreign_spiffe)


def test_svid_signature_tampering_detected(ca, sample_spiffe):
    token = ca.issue_svid(sample_spiffe, ttl_seconds=60.0)
    # Mutate signature
    tampered_token = token.__class__(
        serial_number=token.serial_number,
        spiffe_id=token.spiffe_id,
        issued_at=token.issued_at,
        expires_at=token.expires_at,
        signature="deadbeef" * 8,
    )
    with pytest.raises(ZeroTrustSecurityError, match="signature validation failed"):
        ca.verify_svid(tampered_token)


def test_svid_expiration_enforced(ca, sample_spiffe):
    # Issue token with very short TTL
    token = ca.issue_svid(sample_spiffe, ttl_seconds=0.01)
    time.sleep(0.02)
    assert token.is_expired is True
    with pytest.raises(SVIDExpiredError, match="expired"):
        ca.verify_svid(token)


def test_svid_revocation_enforced(ca, sample_spiffe):
    token = ca.issue_svid(sample_spiffe, ttl_seconds=60.0)
    assert ca.verify_svid(token) is True

    ca.revoke_svid(token.serial_number)
    assert ca.is_revoked(token.serial_number) is True

    with pytest.raises(SVIDRevokedError, match="revoked"):
        ca.verify_svid(token)
