# ZeroTrust-Enclave

**High-Assurance Zero-Trust Microsegmentation Gateway & Ephemeral SPIFFE Workload Attestation Engine**

[![Build Status](https://img.shields.io/badge/tests-22%20passed-brightgreen.svg)](https://github.com/Huighlet/ZeroTrust-Enclave)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Zero AI Slop](https://img.shields.io/badge/codebase-zero%20ai%20slop-black.svg)](https://github.com/Huighlet/ZeroTrust-Enclave)

---

## Executive Summary

Perimeter-centric network security models fundamentally fail in cloud-native, distributed microservice topologies where lateral movement represents the dominant attack vector. **ZeroTrust-Enclave** is an enterprise-grade, high-throughput Zero-Trust control plane implementing cryptographic workload attestation, ephemeral SPIFFE Verifiable Identity Document (SVID) minting, and Attribute-Based Access Control (ABAC) microsegmentation under an invariant of **Default Deny**.

The system replaces implicit network trust (IP-based ACLs and static firewall rules) with cryptographic proofs of executable identity. Workloads must pass binary hash integrity attestation against registered runtime profiles before an Ephemeral Certificate Authority issues short-lived, digitally signed credentials. All intra-cluster and ingress requests undergo microsecond policy evaluation and are permanently recorded to a tamper-evident, SHA-256 chained audit ledger.

---

## System Architecture

```
                                  WORKLOAD ATTESTATION PHASE
                                  
  +------------------+         Executable Image / Hash
  |  Target Service  | -------------------------------------> +-----------------------------+
  | (Candidate Task) |                                        | Workload Attestation Engine |
  +------------------+                                        +-----------------------------+
           |                                                                 |
           |                                                      Verified Integrity Match?
           |                                                                 |
           |                  Issue Ephemeral SVID Token                     v
           + <------------------------------------------------- +-----------------------------+
           |           (Short-Lived HMAC-SHA256 Token)          |   Ephemeral Micro-CA        |
           |                                                    +-----------------------------+
           |
           v
                               AUTHORIZATION & ROUTING PHASE
                               
  +-----------------------------------------------------------------------------------------+
  |                                   ZeroTrust-Enclave Gateway                             |
  |                                                                                         |
  |  +--------------------+      +--------------------+      +---------------------------+  |
  |  |   SVID Verifier    | ---> |    ABAC Engine     | ---> |   Chained Audit Ledger    |  |
  |  |  (Crypto & TTL)    |      |   (Default Deny)   |      |      (Merkle Chain)       |  |
  |  +--------------------+      +--------------------+      +---------------------------+  |
  |            |                           |                               |                |
  +------------|---------------------------|-------------------------------|----------------+
               |                           |                               |
        Signature Valid?             Policy Match?                   Ledger Entry
               |                           |                               |
               +---[ REJECT: DENY ]        +---[ REJECT: DENY ]            v
               |                           |                      +-----------------+
               v                           v                      | Verified Stream |
       [ PROCEED TO TARGET ] <----------------------------------+ | Destination Pod |
```

---

## Mathematical Formulations

### 1. Attribute-Based Access Control (ABAC) Decision Function

Access evaluation enforces an absolute Default Deny invariant over the request context tuple:

$$\mathcal{C} = \langle s, t, a, \mathcal{A} \rangle$$

where:
* $s \in \mathcal{S}$ represents the source workload SPIFFE identifier URI (`spiffe://<domain>/<path>`).
* $t \in \mathcal{T}$ represents the destination workload SPIFFE identifier URI.
* $a \in \Sigma^*$ represents the invocation verb or network action.
* $\mathcal{A} = \{(k_i, v_i)\}$ represents the set of verified environment and deployment attributes.

The authorization decision function $\Phi(\mathcal{C})$ evaluates against ordered policy rules $\mathcal{R} = \{R_1, R_2, \dots, R_m\}$:

$$\Phi(\mathcal{C}) = \begin{cases} \text{ALLOW}, & \exists R_i \in \mathcal{R} \text{ s.t. } M(R_i, \mathcal{C}) \land \text{effect}(R_i) = \text{ALLOW} \\ \text{DENY}, & \text{otherwise (Default Deny Invariant)} \end{cases}$$

where the predicate $M(R, \mathcal{C})$ holds if and only if all pattern constraints are satisfied:

$$M(R, \mathcal{C}) \iff \text{Match}(R_s, s) \land \text{Match}(R_t, t) \land (a \in R_a) \land (R_{\text{attr}} \subseteq \mathcal{A})$$

### 2. SVID Cryptographic Authenticity Signature

Short-lived credentials verify authenticity using keyed HMAC-SHA256 authentication tags:

$$\tau = \text{HMAC-SHA256}\Big(K_{\text{CA}}, \text{serial} \parallel \text{uri} \parallel t_{\text{issued}} \parallel t_{\text{expires}}\Big)$$

Validation enforces strict temporal bounds and constant-time equality:

$$\text{Valid}(\tau, t_{\text{now}}) \iff \Big(t_{\text{now}} \le t_{\text{expires}}\Big) \land \Big(\tau \stackrel{\text{ct}}{=} \text{HMAC-SHA256}(K_{\text{CA}}, \dots)\Big) \land (\text{serial} \notin \mathcal{R}_{\text{revoked}})$$

### 3. Tamper-Evident Ledger Hashing

Every authorization decision produces a permanent record $A_k$ anchored into a cryptographic audit chain:

$$H_0 = 0^{64}$$

$$H_k = \text{SHA-256}\Big(k \parallel t_k \parallel s_k \parallel t_k \parallel a_k \parallel D_k \parallel \text{details}_k \parallel H_{k-1}\Big)$$

Any unauthorized modification of past records renders $H_k \ne H_{k}'$, immediately invalidating audit chain continuity.

---

## Performance & Microsecond Benchmark Results

Benchmarked on Python 3.13 standard runtime across 50,000 iterations:

| Benchmark Phase | Operations / Sec | Mean Latency | Invariant Guaranteed |
| :--- | :--- | :--- | :--- |
| **Workload Binary Attestation (4KB)** | **42,383.9 ops/sec** | **23.594 $\mu$s** | Exact SHA-256 binary match |
| **Ephemeral SVID Issuance & Signing** | **58,557.1 tokens/sec** | **17.077 $\mu$s** | Cryptographic HMAC non-repudiation |
| **Ephemeral SVID Verification** | **75,774.8 checks/sec** | **13.197 $\mu$s** | Constant-time check & TTL bound |
| **ABAC Policy Evaluation** | **197,654.5 evals/sec** | **5.059 $\mu$s** | Strict Default Deny |
| **Full Gateway Pipeline + Audit Chaining** | **25,848.7 req/sec** | **38.687 $\mu$s** | Cryptographic SHA-256 Merkle chain |

---

## Directory Structure

```
ZeroTrust-Enclave/
├── zerotrust/
│   ├── __init__.py           # Package exports and module definitions
│   ├── types.py              # SPIFFE URI (RFC 3986), SVIDToken, WorkloadProfile, AuthContext
│   ├── attestation.py        # Cryptographic binary digest & environment integrity engine
│   ├── ca.py                 # Ephemeral CA, HMAC-SHA256 token minting, and CRL revocation
│   ├── policy.py             # ABAC policy engine, pattern matching, and Default Deny
│   ├── gateway.py            # Unified security gateway with SHA-256 chained audit ledger
│   └── cli.py                # CLI interface and microsecond benchmark suite
├── tests/
│   ├── test_spiffe.py        # RFC 3986 URI validation and trust domain checks
│   ├── test_attestation.py   # Binary tampering detection and environment invariants
│   ├── test_ca.py            # Token issuance, TTL expiration, tampering, and revocation
│   ├── test_policy.py        # Default Deny, wildcard routing, and attribute conditions
│   └── test_gateway.py       # End-to-end attestation-to-authorization lifecycle
├── pyproject.toml            # Build metadata and tool configuration
├── requirements.txt          # Development dependencies (pytest)
├── LICENSE                   # Apache-2.0 Open Source License
└── README.md                 # System specification and documentation
```

---

## Installation & Quickstart

### Prerequisites
* Python 3.11, 3.12, or 3.13
* Virtual environment (recommended)

```bash
git clone https://github.com/Huighlet/ZeroTrust-Enclave.git
cd ZeroTrust-Enclave

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Or on Windows: .venv\Scripts\activate

# Install in editable mode
pip install -e .
```

### Running the Test Suite
```bash
pytest -v
```
Output:
```
tests/test_attestation.py::test_attestation_success_with_bytes PASSED    [  4%]
tests/test_attestation.py::test_attestation_success_with_path PASSED     [  9%]
tests/test_attestation.py::test_attestation_tampered_binary_rejected PASSED [ 13%]
tests/test_attestation.py::test_attestation_unregistered_profile PASSED  [ 18%]
tests/test_attestation.py::test_attestation_environment_mismatch PASSED  [ 22%]
tests/test_ca.py::test_svid_issuance_and_verification PASSED             [ 27%]
tests/test_ca.py::test_cross_trust_domain_issuance_rejected PASSED       [ 31%]
tests/test_ca.py::test_svid_signature_tampering_detected PASSED          [ 36%]
tests/test_ca.py::test_svid_expiration_enforced PASSED                   [ 40%]
tests/test_ca.py::test_svid_revocation_enforced PASSED                   [ 45%]
tests/test_gateway.py::test_gateway_full_attestation_and_authorization PASSED [ 50%]
tests/test_gateway.py::test_gateway_unauthorized_target_rejected PASSED  [ 54%]
tests/test_gateway.py::test_gateway_revocation_denies_authorization PASSED [ 59%]
tests/test_policy.py::test_default_deny_when_no_rules_match PASSED       [ 63%]
tests/test_policy.py::test_rule_matching_allow PASSED                    [ 68%]
tests/test_policy.py::test_action_restriction_enforced PASSED            [ 72%]
tests/test_policy.py::test_required_attributes_mismatch PASSED           [ 77%]
tests/test_spiffe.py::test_spiffe_valid_parsing PASSED                   [ 81%]
tests/test_spiffe.py::test_spiffe_invalid_scheme PASSED                  [ 86%]
tests/test_spiffe.py::test_spiffe_missing_trust_domain PASSED            [ 90%]
tests/test_spiffe.py::test_spiffe_invalid_path PASSED                    [ 95%]
tests/test_spiffe.py::test_spiffe_equality_and_hashing PASSED            [100%]

============================= 22 passed in 1.30s ==============================
```

### Executing Microsecond Benchmarks
```bash
zerotrust bench -n 50000
```

---

## Python API Usage

```python
import hashlib
from zerotrust import ZeroTrustGateway, WorkloadProfile, SpiffeID, PolicyRule, AccessDecision

# 1. Initialize Enclave Gateway for trust domain
gw = ZeroTrustGateway(trust_domain="enclave.mesh")

# 2. Register approved workload profile with SHA-256 image digest
executable_bytes = b"BINARY_MACHINE_CODE_PAYLOAD"
executable_digest = hashlib.sha256(executable_bytes).hexdigest()

profile = WorkloadProfile(
    profile_id="payment-service-v1",
    spiffe_id=SpiffeID.parse("spiffe://enclave.mesh/ns/banking/service/payment"),
    expected_binary_sha256=executable_digest,
    expected_image_path="/opt/bin/payment",
    environment="prod",
)
gw.register_workload(profile)

# 3. Define microsegmentation rules (Default Deny is active)
gw.add_policy_rule(
    PolicyRule(
        rule_id="allow-payment-to-ledger",
        source_pattern="spiffe://enclave.mesh/ns/banking/service/*",
        target_pattern="spiffe://enclave.mesh/ns/core/service/ledger",
        allowed_actions={"TRANSFER"},
        effect=AccessDecision.ALLOW,
    )
)

# 4. Workload attestation and ephemeral SVID issuance
client_svid = gw.authenticate_workload(
    candidate_bytes=executable_bytes,
    profile_id="payment-service-v1",
    environment="prod",
    ttl_seconds=3600.0,
)

# 5. Authorize cross-workload communication
destination = SpiffeID.parse("spiffe://enclave.mesh/ns/core/service/ledger")
decision = gw.authorize_request(
    client_svid=client_svid,
    target_spiffe_id=destination,
    action="TRANSFER",
)
print("Decision:", decision)  # AccessDecision.ALLOW

# 6. Verify ledger chain integrity
assert gw.verify_audit_chain_integrity() is True
```

---

## License

This project is licensed under the Apache 2.0 Open Source License. See [LICENSE](LICENSE) for details.
