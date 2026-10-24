"""
ZeroTrust-Enclave: Command Line Interface & Microsecond Performance Benchmark Suite.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time

from zerotrust.attestation import WorkloadAttestationEngine
from zerotrust.ca import EphemeralCertificateAuthority
from zerotrust.gateway import ZeroTrustGateway
from zerotrust.policy import MicrosegmentationPolicyEngine, PolicyRule
from zerotrust.types import AccessDecision, SpiffeID, WorkloadProfile


def run_benchmark(iterations: int = 50000) -> None:
    """Run rigorous microsecond benchmarks on all Zero-Trust components."""
    print("=" * 76)
    print("ZeroTrust-Enclave: Microsecond Performance & Throughput Benchmark Suite")
    print(f"Iterations: {iterations:,} operations per test")
    print("=" * 76)

    # 1. Attestation SHA-256 Verification
    synthetic_binary = b"\x7fELF" + b"\x00" * 4096  # 4KB synthetic ELF binary
    binary_sha = hashlib.sha256(synthetic_binary).hexdigest()

    attest_engine = WorkloadAttestationEngine()
    spiffe_workload = SpiffeID.parse("spiffe://enclave.internal/ns/core/service/payment")
    profile = WorkloadProfile(
        profile_id="payment-svc-v1",
        spiffe_id=spiffe_workload,
        expected_binary_sha256=binary_sha,
        expected_image_path="/opt/bin/payment",
        environment="prod",
    )
    attest_engine.register_profile(profile)

    t0 = time.perf_counter()
    for _ in range(iterations):
        attest_engine.attest_workload(
            candidate_bytes=synthetic_binary,
            profile_id="payment-svc-v1",
            environment="prod",
        )
    t1 = time.perf_counter()
    dur_attest = t1 - t0
    ops_attest = iterations / dur_attest
    lat_attest_us = (dur_attest / iterations) * 1_000_000

    print(f"[1] Workload Binary Attestation (4KB):")
    print(f"    Throughput: {ops_attest:12,.1f} attests/sec")
    print(f"    Latency:    {lat_attest_us:12.3f} us/attest\n")

    # 2. Ephemeral SVID Issuance
    ca = EphemeralCertificateAuthority(trust_domain="enclave.internal")
    t0 = time.perf_counter()
    sample_tokens = []
    # Collect small sample for verification test to avoid memory bloat
    for i in range(iterations):
        tok = ca.issue_svid(profile, ttl_seconds=3600.0)
        if i < 1000:
            sample_tokens.append(tok)
    t1 = time.perf_counter()
    dur_issue = t1 - t0
    ops_issue = iterations / dur_issue
    lat_issue_us = (dur_issue / iterations) * 1_000_000

    print(f"[2] Ephemeral SVID Issuance & HMAC Signing:")
    print(f"    Throughput: {ops_issue:12,.1f} tokens/sec")
    print(f"    Latency:    {lat_issue_us:12.3f} us/token\n")

    # 3. Ephemeral SVID Verification
    t0 = time.perf_counter()
    tok_len = len(sample_tokens)
    for i in range(iterations):
        ca.verify_svid(sample_tokens[i % tok_len])
    t1 = time.perf_counter()
    dur_verify = t1 - t0
    ops_verify = iterations / dur_verify
    lat_verify_us = (dur_verify / iterations) * 1_000_000

    print(f"[3] Ephemeral SVID Verification (Crypto + Expire Check):")
    print(f"    Throughput: {ops_verify:12,.1f} verifications/sec")
    print(f"    Latency:    {lat_verify_us:12.3f} us/verification\n")

    # 4. Microsegmentation ABAC Policy Evaluation
    policy = MicrosegmentationPolicyEngine()
    policy.add_rule(
        PolicyRule(
            rule_id="allow-finance-to-ledger",
            source_pattern="spiffe://enclave.internal/ns/core/service/*",
            target_pattern="spiffe://enclave.internal/ns/ledger/service/db",
            allowed_actions={"TRANSFER", "QUERY"},
            required_attributes={"tier": "pci-dss"},
            effect=AccessDecision.ALLOW,
        )
    )
    target_spiffe = SpiffeID.parse("spiffe://enclave.internal/ns/ledger/service/db")
    from zerotrust.types import AuthContext
    ctx = AuthContext(
        source_spiffe_id=spiffe_workload,
        target_spiffe_id=target_spiffe,
        action="TRANSFER",
        client_attributes={"tier": "pci-dss"},
    )

    t0 = time.perf_counter()
    for _ in range(iterations):
        policy.evaluate(ctx)
    t1 = time.perf_counter()
    dur_policy = t1 - t0
    ops_policy = iterations / dur_policy
    lat_policy_us = (dur_policy / iterations) * 1_000_000

    print(f"[4] ABAC Microsegmentation Policy Evaluation:")
    print(f"    Throughput: {ops_policy:12,.1f} evals/sec")
    print(f"    Latency:    {lat_policy_us:12.3f} us/eval\n")

    # 5. Full End-to-End Gateway Pipeline with Audit Chaining
    gw = ZeroTrustGateway(trust_domain="enclave.internal")
    gw.register_workload(profile)
    gw.add_policy_rule(
        PolicyRule(
            rule_id="allow-finance-to-ledger",
            source_pattern="spiffe://enclave.internal/ns/core/*",
            target_pattern="spiffe://enclave.internal/ns/ledger/*",
            allowed_actions={"TRANSFER"},
            effect=AccessDecision.ALLOW,
        )
    )
    client_svid = gw.authenticate_workload(
        candidate_bytes=synthetic_binary,
        profile_id="payment-svc-v1",
        environment="prod",
    )

    e2e_iterations = min(iterations, 25000)
    t0 = time.perf_counter()
    for _ in range(e2e_iterations):
        gw.authorize_request(
            client_svid=client_svid,
            target_spiffe_id=target_spiffe,
            action="TRANSFER",
            strict=False,
        )
    t1 = time.perf_counter()
    dur_e2e = t1 - t0
    ops_e2e = e2e_iterations / dur_e2e
    lat_e2e_us = (dur_e2e / e2e_iterations) * 1_000_000

    print(f"[5] Full Gateway Authorization & Audit Chaining:")
    print(f"    Throughput: {ops_e2e:12,.1f} requests/sec")
    print(f"    Latency:    {lat_e2e_us:12.3f} us/request")
    print(f"    Audit Chain Integrity: {gw.verify_audit_chain_integrity()}")
    print("=" * 76)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="zerotrust",
        description="ZeroTrust-Enclave: SPIFFE Workload Attestation & Microsegmentation Gateway",
    )
    subparsers = parser.add_subparsers(dest="command")

    bench_parser = subparsers.add_parser("bench", help="Run microsecond benchmark suite")
    bench_parser.add_argument("-n", "--iterations", type=int, default=50000, help="Number of benchmark iterations")

    serve_parser = subparsers.add_parser("serve", help="Launch FastAPI Zero-Trust Attestation & Policy REST service")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Binding host address")
    serve_parser.add_argument("--port", type=int, default=8443, help="Binding port (default: 8443)")

    args = parser.parse_args()

    if args.command == "serve":
        from zerotrust.server import serve
        serve(host=args.host, port=args.port)
    elif args.command == "bench":
        run_benchmark(iterations=args.iterations)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
