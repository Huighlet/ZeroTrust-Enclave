"""
Production Simulation Harness: ZeroTrust-Enclave SPIFFE Attestation & PEP Gateway.
Simulates a multi-tier zero-trust microservice architecture:
  1. Workload Identity Registration & Ephemeral CA bootstrapping.
  2. Cryptographic binary attestation: minting short-lived HMAC-signed SVID tokens.
  3. ABAC Policy Enforcement Point (PEP): Legitimate service mesh traversal.
  4. Adversary breach simulation:
     - Tampered binary payload blocked at attestation (SHA-256 digest mismatch).
     - Lateral movement breach blocked by Default Deny.
  5. Emergency credential revocation & real-time cache eviction.
  6. Tamper-evident Merkle audit ledger cryptographic verification.
"""

from __future__ import annotations

import hashlib
import sys
import time
from typing import Dict, List

from zerotrust.gateway import ZeroTrustGateway
from zerotrust.policy import PolicyRule
from zerotrust.types import (
    AccessDecision,
    AccessDeniedError,
    AttestationFailedError,
    SpiffeID,
    SVIDRevokedError,
    WorkloadProfile,
)


def run_enclave_simulation() -> None:
    print("=" * 70)
    print("ZEROTRUST-ENCLAVE: ZERO-TRUST SERVICE MESH SIMULATION")
    print("=" * 70)

    # 1. Initialize Enclave Gateway & CA
    print("\n[Phase 1] Initializing Zero-Trust Enclave & Ephemeral CA...")
    gateway = ZeroTrustGateway(trust_domain="enclave.internal")

    # 2. Register Workload Profiles
    print("\n[Phase 2] Registering Multi-Tier Approved Workload Profiles...")
    bin_frontend = b"ELF_FRONTEND_PROD_RELEASE_2026" * 16
    bin_gateway = b"ELF_API_GATEWAY_RELEASE_2026" * 16
    bin_payment = b"ELF_PAYMENT_CORE_RELEASE_2026" * 16
    bin_vault = b"ELF_DATABASE_VAULT_RELEASE_2026" * 16

    profiles = [
        ("frontend-prod", "spiffe://enclave.internal/ns/web/service/frontend", bin_frontend, "/app/frontend"),
        ("gateway-prod", "spiffe://enclave.internal/ns/edge/service/gateway", bin_gateway, "/app/gateway"),
        ("payment-prod", "spiffe://enclave.internal/ns/finance/service/payment", bin_payment, "/app/payment"),
        ("vault-prod", "spiffe://enclave.internal/ns/data/service/vault", bin_vault, "/app/vault"),
    ]

    for pid, uri, b_data, img in profiles:
        gateway.register_workload(
            WorkloadProfile(
                profile_id=pid,
                spiffe_id=SpiffeID.parse(uri),
                expected_binary_sha256=hashlib.sha256(b_data).hexdigest(),
                expected_image_path=img,
                environment="prod",
            )
        )
    print(f"  Registered {len(profiles)} tier profiles with golden binary SHA-256 fingerprints.")

    # 3. Configure ABAC Microsegmentation Policies (Default Deny)
    print("\n[Phase 3] Configuring ABAC Microsegmentation Policies...")
    gateway.add_policy_rule(
        PolicyRule(
            rule_id="frontend-to-gateway",
            source_pattern="spiffe://enclave.internal/ns/web/service/frontend",
            target_pattern="spiffe://enclave.internal/ns/edge/service/gateway",
            allowed_actions={"FORWARD"},
            description="Permit web frontend to call edge gateway",
        )
    )
    gateway.add_policy_rule(
        PolicyRule(
            rule_id="gateway-to-payment",
            source_pattern="spiffe://enclave.internal/ns/edge/service/gateway",
            target_pattern="spiffe://enclave.internal/ns/finance/service/payment",
            allowed_actions={"PROCESS_CHECKOUT"},
            description="Permit edge gateway to invoke payment service",
        )
    )
    gateway.add_policy_rule(
        PolicyRule(
            rule_id="payment-to-vault",
            source_pattern="spiffe://enclave.internal/ns/finance/service/payment",
            target_pattern="spiffe://enclave.internal/ns/data/service/vault",
            allowed_actions={"DEBIT", "CREDIT"},
            description="Permit payment service to query database vault",
        )
    )
    print("  Active policies: 3 strict rules. Default Deny enforced across all unmapped vectors.")

    # 4. Attest Workloads and Mint Ephemeral SVIDs
    print("\n[Phase 4] Attesting Workloads & Minting Ephemeral SVID Tokens...")
    svid_frontend = gateway.authenticate_workload(candidate_bytes=bin_frontend, profile_id="frontend-prod")
    svid_gateway = gateway.authenticate_workload(candidate_bytes=bin_gateway, profile_id="gateway-prod")
    svid_payment = gateway.authenticate_workload(candidate_bytes=bin_payment, profile_id="payment-prod")
    svid_vault = gateway.authenticate_workload(candidate_bytes=bin_vault, profile_id="vault-prod")
    print(f"  Minted SVID for Payment: {svid_payment.serial_number} (Signature: {svid_payment.signature[:16]}...)")

    # 5. Legitimate Mesh Authorization
    print("\n[Phase 5] Evaluating Legitimate Authorized Flow (Frontend -> Gateway -> Payment -> Vault)...")
    dec1 = gateway.authorize_request(svid_frontend, SpiffeID.parse("spiffe://enclave.internal/ns/edge/service/gateway"), "FORWARD")
    dec2 = gateway.authorize_request(svid_gateway, SpiffeID.parse("spiffe://enclave.internal/ns/finance/service/payment"), "PROCESS_CHECKOUT")
    dec3 = gateway.authorize_request(svid_payment, SpiffeID.parse("spiffe://enclave.internal/ns/data/service/vault"), "DEBIT")
    assert dec1 == AccessDecision.ALLOW and dec2 == AccessDecision.ALLOW and dec3 == AccessDecision.ALLOW
    print("  [PERMIT] Complete legitimate flow authorized across all 3 hops.")

    # 6. Attack Simulation: Tampered Binary
    print("\n[Phase 6] Attack Vector 1: Maliciously Tampered Binary Container...")
    tampered_bytes = bin_frontend + b"\x90\x90_BACKDOOR_INJECTION"
    try:
        gateway.authenticate_workload(candidate_bytes=tampered_bytes, profile_id="frontend-prod")
        raise AssertionError("Tampered binary must fail attestation!")
    except AttestationFailedError:
        print("  [BLOCKED] Attestation Failed: Binary SHA-256 mismatch prevented SVID token minting.")

    # 7. Attack Simulation: Lateral Movement Breach Attempt
    print("\n[Phase 7] Attack Vector 2: Lateral Movement Bypass (Frontend attempting direct Vault access)...")
    try:
        gateway.authorize_request(svid_frontend, SpiffeID.parse("spiffe://enclave.internal/ns/data/service/vault"), "DEBIT")
        raise AssertionError("Lateral movement must be blocked!")
    except AccessDeniedError:
        print("  [BLOCKED] Access Denied: Default Deny policy prevented direct web-to-vault data exfiltration.")

    # 8. Emergency SVID Revocation
    print("\n[Phase 8] Attack Vector 3: Compromised Key Containment & Emergency Revocation...")
    gateway.ca.revoke_svid(svid_gateway.serial_number)
    try:
        gateway.authorize_request(svid_gateway, SpiffeID.parse("spiffe://enclave.internal/ns/finance/service/payment"), "PROCESS_CHECKOUT")
        raise AssertionError("Revoked token must be rejected!")
    except SVIDRevokedError:
        print(f"  [REVOKED] Revocation Verified: Token '{svid_gateway.serial_number}' successfully blacklisted.")

    # 9. Audit Ledger Cryptographic Verification
    print("\n[Phase 9] Verifying Cryptographic Audit Ledger Integrity...")
    is_valid = gateway.verify_audit_chain_integrity()
    audit_len = len(gateway.audit_chain)
    head_hash = gateway.audit_chain[-1].record_hash

    print(f"  Total Audit Records:     {audit_len}")
    print(f"  Ledger Chain Head:       {head_hash[:24]}...")
    print(f"  Cryptographic Integrity: {'100% VALID' if is_valid else 'CORRUPT'}")

    assert is_valid, "Cryptographic audit chain must remain intact!"
    print("\n[PASS] Zero-Trust Enclave Service Mesh Simulation passed successfully.")
    print("=" * 70)


if __name__ == "__main__":
    run_enclave_simulation()
