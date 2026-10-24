"""
ZeroTrust-Enclave: Production SPIFFE Workload Attestation & Policy Gateway Server.
Provides binary cryptographic attestation, ephemeral HMAC SVID minting,
ABAC microsegmentation policy enforcement, tamper-evident audit ledger chaining, and an interactive developer UI.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from zerotrust.gateway import ZeroTrustGateway
from zerotrust.policy import PolicyRule
from zerotrust.types import (
    AccessDecision,
    AccessDeniedError,
    AttestationFailedError,
    SpiffeID,
    SVIDExpiredError,
    SVIDRevokedError,
    SVIDToken,
    WorkloadProfile,
    ZeroTrustSecurityError,
)

# ---------------------------------------------------------
# Request / Response Schemas
# ---------------------------------------------------------

class RegisterWorkloadRequest(BaseModel):
    profile_id: str = Field(..., description="Unique workload profile identifier")
    spiffe_uri: str = Field(..., description="SPIFFE ID RFC 3986 URI (e.g. 'spiffe://enclave.internal/ns/finance/service/ledger')")
    expected_binary_sha256: str = Field(..., description="Expected SHA-256 digest of approved binary")
    expected_image_path: str = Field(..., description="Expected container/filesystem image path")
    environment: str = Field("prod", description="Execution environment: 'prod', 'staging', 'dev'")
    attributes: Optional[Dict[str, str]] = Field(None, description="Static security tags (e.g. tier, data_classification)")


class AttestRequest(BaseModel):
    profile_id: str = Field(..., description="Registered workload profile identifier to attest against")
    candidate_hex: str = Field(..., description="Candidate binary bytes in hex format")
    environment: str = Field("prod", description="Execution environment")
    ttl_seconds: Optional[float] = Field(3600.0, description="Requested SVID credential validity duration in seconds")


class AuthorizeRequest(BaseModel):
    svid_serial: str = Field(..., description="Serial number of active SVID credential")
    target_spiffe_uri: str = Field(..., description="Destination service SPIFFE URI")
    action: str = Field(..., description="Intended operation: 'READ', 'WRITE', 'TRANSFER', 'ADMIN'")
    client_attributes: Optional[Dict[str, str]] = Field(None, description="Dynamic client metadata attributes")


class AddPolicyRequest(BaseModel):
    rule_id: str = Field(..., description="Unique policy rule identifier")
    source_pattern: str = Field(..., description="Source SPIFFE wildcard pattern (e.g. 'spiffe://enclave.internal/ns/finance/*')")
    target_pattern: str = Field(..., description="Target SPIFFE wildcard pattern")
    allowed_actions: List[str] = Field(..., description="Permitted actions (e.g. ['READ', 'TRANSFER'])")
    required_attributes: Optional[Dict[str, str]] = Field(None, description="Required ABAC attribute assertions")
    description: Optional[str] = Field("", description="Human-readable rule intent")


# ---------------------------------------------------------
# Gateway Initialization
# ---------------------------------------------------------

app = FastAPI(
    title="ZeroTrust-Enclave Attestation & Security Gateway",
    description="Institutional Zero-Trust Policy Enforcement Point (PEP) with binary SHA-256 workload attestation, ephemeral SVID issuance, ABAC microsegmentation, and cryptographic audit chaining.",
    version="1.0.0",
)

gateway = ZeroTrustGateway(trust_domain="enclave.internal")

# Cache issued SVIDs in memory for fast serial lookup
issued_tokens: Dict[str, SVIDToken] = {}

# Pre-seed institutional profiles and rules
_ledger_spiffe = SpiffeID.parse("spiffe://enclave.internal/ns/finance/service/ledger")
_payment_spiffe = SpiffeID.parse("spiffe://enclave.internal/ns/finance/service/payment")

_sample_binary = b"\x7fELF" + b"PROD_LEDGER_BINARY_PAYLOAD_V1" * 32
_sample_sha = hashlib.sha256(_sample_binary).hexdigest()

gateway.register_workload(
    WorkloadProfile(
        profile_id="ledger-core-prod",
        spiffe_id=_ledger_spiffe,
        expected_binary_sha256=_sample_sha,
        expected_image_path="/opt/bin/titanledger",
        environment="prod",
        attributes={"tier": "tier-0", "classification": "financial-core"},
    )
)

gateway.add_policy_rule(
    PolicyRule(
        rule_id="allow-payment-to-ledger",
        source_pattern="spiffe://enclave.internal/ns/finance/*",
        target_pattern="spiffe://enclave.internal/ns/finance/service/ledger",
        allowed_actions={"READ", "POST", "TRANSFER"},
        description="Allow authenticated financial services to invoke core ledger",
    )
)


# ---------------------------------------------------------
# Developer UI Dashboard
# ---------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def zerotrust_dashboard():
    """Interactive Zero-Trust Enclave Security Console."""
    profiles = gateway.attestation._profiles
    profiles_rows = "".join(
        f"<tr><td><code>{p.profile_id}</code></td><td><strong>{p.spiffe_id.uri}</strong></td><td><code>{p.expected_binary_sha256[:16]}...</code></td><td>{p.environment}</td></tr>"
        for p in profiles.values()
    )

    audit_chain = gateway.audit_chain[-5:]
    audit_rows = "".join(
        f"<tr><td>#{a.index}</td><td><code>{a.source_uri}</code> &rarr; <code>{a.target_uri}</code></td><td><strong>{a.action}</strong></td><td style='color:{'#34d399' if a.decision == AccessDecision.ALLOW else '#ef4444'}'>{a.decision}</td><td><code>{a.record_hash[:16]}...</code></td></tr>"
        for a in audit_chain
    )
    if not audit_rows:
        audit_rows = "<tr><td colspan='5' style='text-align:center;color:#9ca3af;'>No audit records yet. Authenticate workload to begin.</td></tr>"

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ZeroTrust-Enclave Security Console</title>
        <meta charset="utf-8">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0b0f19; color: #f3f4f6; margin: 0; padding: 32px; }}
            .container {{ max-width: 1050px; margin: 0 auto; background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 28px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
            h1 {{ color: #a855f7; margin-top: 0; font-size: 24px; font-weight: 600; }}
            p {{ color: #9ca3af; font-size: 14px; line-height: 1.5; }}
            .metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 20px 0; }}
            .card {{ background: #1f2937; padding: 14px; border-radius: 6px; border-left: 3px solid #a855f7; }}
            .card-label {{ font-size: 11px; text-transform: uppercase; color: #9ca3af; }}
            .card-val {{ font-size: 22px; font-weight: 700; color: #f9fafb; margin-top: 4px; }}
            table {{ width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 13px; }}
            th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #374151; }}
            th {{ background: #1f2937; color: #9ca3af; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
            .btn {{ display: inline-block; padding: 9px 16px; border-radius: 6px; background: #9333ea; color: #ffffff; text-decoration: none; font-size: 13px; font-weight: 600; margin-right: 8px; }}
            .btn:hover {{ background: #7e22ce; }}
            code {{ background: #1f2937; padding: 2px 6px; border-radius: 4px; color: #d8b4fe; }}
            pre {{ background: #030712; padding: 14px; border-radius: 6px; color: #d8b4fe; font-size: 12px; overflow-x: auto; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>ZeroTrust-Enclave Policy Enforcement & Attestation Authority</h1>
            <p>Institutional Zero-Trust Gateway providing binary SHA-256 workload attestation, ephemeral SVID token issuance, ABAC microsegmentation, and tamper-evident audit chaining.</p>

            <div class="metrics">
                <div class="card">
                    <div class="card-label">Trust Domain</div>
                    <div class="card-val" style="font-size:16px; word-break:break-all;">{gateway.trust_domain}</div>
                </div>
                <div class="card">
                    <div class="card-label">Active Workloads</div>
                    <div class="card-val">{len(profiles):,}</div>
                </div>
                <div class="card">
                    <div class="card-label">Audit Ledger Nodes</div>
                    <div class="card-val">{len(gateway.audit_chain):,}</div>
                </div>
                <div class="card">
                    <div class="card-label">Chain Integrity</div>
                    <div class="card-val" style="color: {'#34d399' if gateway.verify_audit_chain_integrity() else '#ef4444'}">{'VALID' if gateway.verify_audit_chain_integrity() else 'CORRUPTED'}</div>
                </div>
            </div>

            <p>
                <a href="/docs" class="btn">Explore OpenAPI / Swagger &rarr;</a>
                <a href="/v1/audit/chain" class="btn" style="background: #374151;">Full Audit Ledger</a>
                <a href="/v1/policies" class="btn" style="background: #374151;">Microsegmentation Policies</a>
            </p>

            <h3>Registered Workload Profiles</h3>
            <table>
                <thead>
                    <tr><th>Profile ID</th><th>SPIFFE URI</th><th>Expected Binary SHA-256</th><th>Environment</th></tr>
                </thead>
                <tbody>
                    {profiles_rows}
                </tbody>
            </table>

            <h3>Recent Cryptographic Authorization Ledger</h3>
            <table>
                <thead>
                    <tr><th>Index</th><th>Source &rarr; Target</th><th>Action</th><th>Decision</th><th>Merkle Hash</th></tr>
                </thead>
                <tbody>
                    {audit_rows}
                </tbody>
            </table>

            <h3>Quick Binary Attestation Example</h3>
            <pre>curl -X POST http://localhost:8443/v1/attest \\
  -H "Content-Type: application/json" \\
  -d '{{"profile_id": "ledger-core-prod", "candidate_hex": "{_sample_binary.hex()[:32]}...", "ttl_seconds": 3600}}'</pre>
        </div>
    </body>
    </html>
    """


# ---------------------------------------------------------
# Health & Status Endpoints
# ---------------------------------------------------------

@app.get("/health")
def health():
    """Gateway liveness & cryptographic audit integrity check."""
    return {
        "status": "HEALTHY",
        "timestamp_ns": time.time_ns(),
        "trust_domain": gateway.trust_domain,
        "profiles_count": len(gateway.attestation._profiles),
        "audit_chain_length": len(gateway.audit_chain),
        "audit_chain_verified": gateway.verify_audit_chain_integrity(),
    }


# ---------------------------------------------------------
# Workload Management & Attestation
# ---------------------------------------------------------

@app.post("/v1/workloads/register", status_code=status.HTTP_201_CREATED)
def register_workload(req: RegisterWorkloadRequest):
    """Register an approved workload profile with its expected binary hash and image path."""
    try:
        spiffe_id = SpiffeID.parse(req.spiffe_uri)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid SPIFFE URI: {e}")

    profile = WorkloadProfile(
        profile_id=req.profile_id,
        spiffe_id=spiffe_id,
        expected_binary_sha256=req.expected_binary_sha256.lower(),
        expected_image_path=req.expected_image_path,
        environment=req.environment,
        attributes=req.attributes or {},
    )
    gateway.register_workload(profile)
    return {"registered": True, "profile_id": req.profile_id, "spiffe_uri": spiffe_id.uri}


@app.post("/v1/attest")
def attest_workload(req: AttestRequest):
    """
    Attest candidate binary bytes against registered profile.
    Issues a short-lived cryptographic SVID credential from the Ephemeral CA upon verification.
    """
    try:
        candidate_bytes = bytes.fromhex(req.candidate_hex.strip().replace(" ", ""))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid hex candidate bytes: {e}")

    try:
        svid = gateway.authenticate_workload(
            candidate_bytes=candidate_bytes,
            profile_id=req.profile_id,
            environment=req.environment,
            ttl_seconds=req.ttl_seconds or 3600.0,
        )
        # Store active credential for authorization lookups
        issued_tokens[svid.serial_number] = svid

        return {
            "attested": True,
            "serial_number": svid.serial_number,
            "spiffe_uri": svid.spiffe_id.uri,
            "issued_at": svid.issued_at,
            "expires_at": svid.expires_at,
            "ttl_seconds": round(svid.expires_at - svid.issued_at, 2),
            "signature": svid.signature,
            "is_valid": svid.is_valid,
        }
    except AttestationFailedError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except KeyError as e:
        raise HTTPException(status_code=404, detail=f"Profile '{req.profile_id}' not found.")


# ---------------------------------------------------------
# Zero-Trust Authorization & Microsegmentation
# ---------------------------------------------------------

@app.post("/v1/authorize")
def authorize_request(req: AuthorizeRequest):
    """
    Zero-Trust Policy Enforcement Point (PEP).
    Validates client SVID token authenticity/expiration and evaluates ABAC policy under Default Deny.
    """
    token = issued_tokens.get(req.svid_serial)
    if not token:
        raise HTTPException(status_code=404, detail=f"SVID Serial '{req.svid_serial}' not recognized or expired.")

    try:
        target_id = SpiffeID.parse(req.target_spiffe_uri)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid target SPIFFE URI: {e}")

    try:
        decision = gateway.authorize_request(
            client_svid=token,
            target_spiffe_id=target_id,
            action=req.action,
            client_attributes=req.client_attributes or {},
            strict=True,
        )
        latest_audit = gateway.audit_chain[-1]
        return {
            "decision": decision.value,
            "source_spiffe_uri": token.spiffe_id.uri,
            "target_spiffe_uri": target_id.uri,
            "action": req.action,
            "audit_record_index": latest_audit.index,
            "audit_hash": latest_audit.record_hash,
        }
    except AccessDeniedError as e:
        latest_audit = gateway.audit_chain[-1]
        return {
            "decision": "DENY",
            "source_spiffe_uri": token.spiffe_id.uri,
            "target_spiffe_uri": target_id.uri,
            "action": req.action,
            "reason": str(e),
            "audit_record_index": latest_audit.index,
            "audit_hash": latest_audit.record_hash,
        }
    except ZeroTrustSecurityError as e:
        raise HTTPException(status_code=401, detail=str(e))


@app.get("/v1/policies")
def list_policies():
    """List all registered microsegmentation rules."""
    rules = [
        {
            "rule_id": r.rule_id,
            "source_pattern": r.source_pattern,
            "target_pattern": r.target_pattern,
            "allowed_actions": list(r.allowed_actions),
            "required_attributes": r.required_attributes,
            "effect": r.effect.value,
            "description": r.description,
        }
        for r in gateway.policy._rules.values()
    ]
    return {"count": len(rules), "rules": rules}


@app.post("/v1/policies", status_code=status.HTTP_201_CREATED)
def add_policy_rule(req: AddPolicyRequest):
    """Add a microsegmentation policy rule."""
    rule = PolicyRule(
        rule_id=req.rule_id,
        source_pattern=req.source_pattern,
        target_pattern=req.target_pattern,
        allowed_actions=set(req.allowed_actions),
        required_attributes=req.required_attributes or {},
        description=req.description or "",
    )
    gateway.add_policy_rule(rule)
    return {"registered": True, "rule_id": req.rule_id}


@app.get("/v1/audit/chain")
def get_audit_ledger():
    """Retrieve complete chained audit records."""
    records = [r.to_dict() for r in gateway.audit_chain]
    return {
        "count": len(records),
        "is_integrity_valid": gateway.verify_audit_chain_integrity(),
        "records": records,
    }


@app.get("/v1/audit/verify")
def verify_audit():
    """Cryptographically verify the SHA-256 audit ledger."""
    is_valid = gateway.verify_audit_chain_integrity()
    return {
        "is_valid": is_valid,
        "chain_length": len(gateway.audit_chain),
        "head_hash": gateway.audit_chain[-1].record_hash if gateway.audit_chain else gateway.GENESIS_HASH,
    }


def serve(host: str = "0.0.0.0", port: int = 8443):
    """Launch ZeroTrust REST gateway service."""
    import uvicorn
    uvicorn.run("zerotrust.server:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    serve()
