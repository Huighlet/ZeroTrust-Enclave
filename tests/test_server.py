"""
Unit & Integration Tests for ZeroTrust-Enclave REST Attestation & Policy Service.
"""

import hashlib
import pytest
from starlette.testclient import TestClient
from zerotrust.server import app, _sample_binary, _sample_sha


@pytest.fixture
def client():
    return TestClient(app)


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert "trust_domain" in data
    assert data["audit_chain_verified"] is True


def test_dashboard_ui(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "ZeroTrust-Enclave Policy Enforcement & Attestation Authority" in response.text


def test_register_and_attest_workload(client):
    # 1. Attest valid candidate binary matching pre-seeded profile 'ledger-core-prod'
    attest_resp = client.post("/v1/attest", json={
        "profile_id": "ledger-core-prod",
        "candidate_hex": _sample_binary.hex(),
        "ttl_seconds": 1800,
    })
    assert attest_resp.status_code == 200
    attest_data = attest_resp.json()
    assert attest_data["attested"] is True
    assert "serial_number" in attest_data
    assert attest_data["spiffe_uri"] == "spiffe://enclave.internal/ns/finance/service/ledger"

    # 2. Tampered candidate binary should be rejected with HTTP 403
    tampered_bytes = _sample_binary + b"MALICIOUS_HOOK"
    bad_resp = client.post("/v1/attest", json={
        "profile_id": "ledger-core-prod",
        "candidate_hex": tampered_bytes.hex(),
    })
    assert bad_resp.status_code == 403


def test_zero_trust_authorization_pep(client):
    # First, authenticate workload to get active SVID
    attest_resp = client.post("/v1/attest", json={
        "profile_id": "ledger-core-prod",
        "candidate_hex": _sample_binary.hex(),
    })
    svid_serial = attest_resp.json()["serial_number"]

    # 1. Authorize action allowed by pre-seeded rule:
    # source: "spiffe://enclave.internal/ns/finance/*" -> target: "spiffe://enclave.internal/ns/finance/service/ledger"
    auth_resp = client.post("/v1/authorize", json={
        "svid_serial": svid_serial,
        "target_spiffe_uri": "spiffe://enclave.internal/ns/finance/service/ledger",
        "action": "TRANSFER",
    })
    assert auth_resp.status_code == 200
    assert auth_resp.json()["decision"] == "ALLOW"
    assert "audit_hash" in auth_resp.json()

    # 2. Default Deny: Unauthorized action "DELETE" should return DENY
    deny_resp = client.post("/v1/authorize", json={
        "svid_serial": svid_serial,
        "target_spiffe_uri": "spiffe://enclave.internal/ns/finance/service/ledger",
        "action": "DELETE",
    })
    assert deny_resp.status_code == 200
    assert deny_resp.json()["decision"] == "DENY"


def test_audit_chain_and_verify(client):
    # Query complete audit ledger
    chain_resp = client.get("/v1/audit/chain")
    assert chain_resp.status_code == 200
    chain_data = chain_resp.json()
    assert chain_data["is_integrity_valid"] is True
    assert chain_data["count"] >= 1

    # Verify cryptographic hash integrity
    verify_resp = client.get("/v1/audit/verify")
    assert verify_resp.status_code == 200
    assert verify_resp.json()["is_valid"] is True
