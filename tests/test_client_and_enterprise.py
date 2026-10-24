"""
Enterprise and Client SDK tests for ZeroTrust-Enclave.
Validates Pillar 1 (Enterprise Middleware & Metrics), Pillar 2 (SVID Revocation & Audit Verification), and Pillar 3 (Client SDK).
"""

import pytest
from starlette.testclient import TestClient

from zerotrust import server
from zerotrust.client import ZeroTrustClient


@pytest.fixture
def test_client() -> TestClient:
    return TestClient(server.app)


def test_prometheus_metrics_endpoint(test_client: TestClient):
    resp = test_client.get("/metrics")
    assert resp.status_code == 200
    text = resp.text
    assert "zerotrust_profiles_active" in text
    assert "zerotrust_policies_active" in text
    assert "zerotrust_audit_chain_length" in text


def test_svid_emergency_revocation(test_client: TestClient):
    # 1. Attest workload
    sample_binary = b"\x7fELF" + b"PROD_LEDGER_BINARY_PAYLOAD_V1" * 32
    att_resp = test_client.post("/v1/attest", json={
        "profile_id": "ledger-core-prod",
        "candidate_hex": sample_binary.hex(),
        "environment": "prod",
    })
    assert att_resp.status_code == 200
    serial = att_resp.json()["serial_number"]

    # 2. Revoke SVID
    rev_resp = test_client.post(f"/v1/svid/revoke/{serial}")
    assert rev_resp.status_code == 200
    assert rev_resp.json()["status"] == "REVOKED"

    # 3. Verify subsequent authorization is rejected
    auth_resp = test_client.post("/v1/authorize", json={
        "svid_serial": serial,
        "target_spiffe_uri": "spiffe://enclave.internal/ns/finance/service/ledger",
        "action": "READ",
    })
    assert auth_resp.status_code == 401


def test_zerotrust_python_client_sdk(test_client: TestClient):
    client = ZeroTrustClient(http_client=test_client)

    # 1. Attest
    sample_binary = b"\x7fELF" + b"PROD_LEDGER_BINARY_PAYLOAD_V1" * 32
    att = client.attest_workload("ledger-core-prod", sample_binary)
    assert att["attested"] is True
    serial = att["serial_number"]

    # 2. Authorize
    auth = client.authorize(
        svid_serial=serial,
        target_spiffe_uri="spiffe://enclave.internal/ns/finance/service/ledger",
        action="READ",
    )
    assert "decision" in auth

    # 3. Export audit
    audit = client.export_audit_chain()
    assert audit["is_integrity_valid"] is True
    client.close()
