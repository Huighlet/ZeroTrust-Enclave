"""
Tests for SPIFFE ID URI parsing and validation (RFC 3986).
"""

import pytest
from zerotrust.types import SpiffeID


def test_spiffe_valid_parsing():
    spiffe = SpiffeID.parse("spiffe://acme.internal/ns/prod/service/payments")
    assert spiffe.trust_domain == "acme.internal"
    assert spiffe.path == "/ns/prod/service/payments"
    assert str(spiffe) == "spiffe://acme.internal/ns/prod/service/payments"
    assert spiffe.uri == "spiffe://acme.internal/ns/prod/service/payments"


def test_spiffe_invalid_scheme():
    with pytest.raises(ValueError, match="Invalid SPIFFE scheme"):
        SpiffeID.parse("https://acme.internal/ns/prod/service")


def test_spiffe_missing_trust_domain():
    with pytest.raises(ValueError):
        SpiffeID.parse("spiffe:///ns/prod/service")


def test_spiffe_invalid_path():
    with pytest.raises(ValueError, match="must begin with '/'"):
        SpiffeID(trust_domain="acme.internal", path="ns/prod/service")


def test_spiffe_equality_and_hashing():
    id1 = SpiffeID.parse("spiffe://domain.com/svc/a")
    id2 = SpiffeID(trust_domain="domain.com", path="/svc/a")
    id3 = SpiffeID.parse("spiffe://domain.com/svc/b")

    assert id1 == id2
    assert id1 != id3
    assert hash(id1) == hash(id2)
    s = {id1, id2, id3}
    assert len(s) == 2
