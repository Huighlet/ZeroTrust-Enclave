"""
ZeroTrust-Enclave: Zero-Trust Security Gateway.
Coordinates workload attestation, ephemeral mTLS credential issuance, and ABAC policy enforcement.
Maintains a cryptographically chained audit log of all authorization decisions.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from zerotrust.attestation import WorkloadAttestationEngine
from zerotrust.ca import EphemeralCertificateAuthority
from zerotrust.policy import MicrosegmentationPolicyEngine, PolicyRule
from zerotrust.types import (
    AccessDecision,
    AccessDeniedError,
    AttestationFailedError,
    AuthContext,
    SpiffeID,
    SVIDExpiredError,
    SVIDRevokedError,
    SVIDToken,
    WorkloadProfile,
    ZeroTrustSecurityError,
)


@dataclasses.dataclass(slots=True, frozen=True)
class AuditRecord:
    """Tamper-evident chained audit ledger record."""
    index: int
    timestamp: float
    source_uri: str
    target_uri: str
    action: str
    decision: AccessDecision
    details: str
    prev_hash: str
    record_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "source_uri": self.source_uri,
            "target_uri": self.target_uri,
            "action": self.action,
            "decision": str(self.decision),
            "details": self.details,
            "prev_hash": self.prev_hash,
            "record_hash": self.record_hash,
        }


class ZeroTrustGateway:
    """
    Unified Zero-Trust Security Gateway.
    Integrates Workload Attestation, Ephemeral CA, and Microsegmentation Policy Enforcement.
    """

    GENESIS_HASH = "0" * 64

    def __init__(
        self,
        trust_domain: str,
        signing_key: Optional[bytes] = None,
        default_ttl_seconds: float = 3600.0,
    ) -> None:
        self.trust_domain = trust_domain
        self.attestation = WorkloadAttestationEngine()
        self.ca = EphemeralCertificateAuthority(
            trust_domain=trust_domain,
            signing_key=signing_key,
            default_ttl_seconds=default_ttl_seconds,
        )
        self.policy = MicrosegmentationPolicyEngine()
        self._audit_chain: List[AuditRecord] = []

    @property
    def audit_chain(self) -> List[AuditRecord]:
        return list(self._audit_chain)

    def register_workload(self, profile: WorkloadProfile) -> None:
        """Register an approved workload profile."""
        self.attestation.register_profile(profile)

    def add_policy_rule(self, rule: PolicyRule) -> None:
        """Add a microsegmentation rule."""
        self.policy.add_rule(rule)

    def authenticate_workload(
        self,
        candidate_bytes: Optional[bytes] = None,
        candidate_path: Optional[str | Path] = None,
        spiffe_id: Optional[SpiffeID] = None,
        profile_id: Optional[str] = None,
        environment: str = "prod",
        ttl_seconds: Optional[float] = None,
    ) -> SVIDToken:
        """
        Attest a workload binary and issue a cryptographic SVID credential upon success.
        """
        # Step 1: Verify binary identity against registered profile
        profile = self.attestation.attest_workload(
            candidate_bytes=candidate_bytes,
            candidate_path=candidate_path,
            spiffe_id=spiffe_id,
            profile_id=profile_id,
            environment=environment,
        )

        # Step 2: Issue short-lived SVID token from Ephemeral CA
        svid = self.ca.issue_svid(profile, ttl_seconds=ttl_seconds)

        # Record attestation success in audit chain
        self._append_audit_record(
            source_uri=profile.spiffe_id.uri,
            target_uri=f"spiffe://{self.trust_domain}/ca/issue",
            action="ATTEST_AND_ISSUE",
            decision=AccessDecision.ALLOW,
            details=f"Issued SVID serial={svid.serial_number} ttl={svid.expires_at - svid.issued_at:.0f}s",
        )

        return svid

    def authorize_request(
        self,
        client_svid: SVIDToken,
        target_spiffe_id: SpiffeID,
        action: str,
        client_attributes: Optional[Dict[str, str]] = None,
        strict: bool = True,
    ) -> AccessDecision:
        """
        Enforce Zero-Trust authorization for an incoming workload communication request.

        1. Validates client SVID authenticity, expiration, and revocation status.
        2. Evaluates Attribute-Based Access Control (ABAC) policy under Default Deny.
        3. Records decision in the tamper-evident audit ledger.
        """
        # Validate SVID integrity with CA
        try:
            self.ca.verify_svid(client_svid)
        except ZeroTrustSecurityError as exc:
            self._append_audit_record(
                source_uri=client_svid.spiffe_id.uri,
                target_uri=target_spiffe_id.uri,
                action=action,
                decision=AccessDecision.DENY,
                details=f"SVID validation failed: {str(exc)}",
            )
            if strict:
                raise
            return AccessDecision.DENY

        # Evaluate policy
        context = AuthContext(
            source_spiffe_id=client_svid.spiffe_id,
            target_spiffe_id=target_spiffe_id,
            action=action,
            client_attributes=client_attributes or {},
        )

        decision, matched_rule = self.policy.evaluate(context)
        details = (
            f"Rule '{matched_rule.rule_id}' matched"
            if matched_rule
            else "Default Deny: no matching rule found"
        )

        self._append_audit_record(
            source_uri=client_svid.spiffe_id.uri,
            target_uri=target_spiffe_id.uri,
            action=action,
            decision=decision,
            details=details,
        )

        if decision != AccessDecision.ALLOW and strict:
            raise AccessDeniedError(
                f"Access denied from '{client_svid.spiffe_id}' to '{target_spiffe_id}' "
                f"for action '{action}' ({details})."
            )

        return decision

    def revoke_svid(self, serial_number: str) -> None:
        """Revoke an active credential."""
        self.ca.revoke_svid(serial_number)
        self._append_audit_record(
            source_uri="system",
            target_uri=f"spiffe://{self.trust_domain}/ca/revoke",
            action="REVOKE",
            decision=AccessDecision.ALLOW,
            details=f"Revoked SVID serial={serial_number}",
        )

    def verify_audit_chain_integrity(self) -> bool:
        """
        Cryptographically verify the integrity of the audit ledger chain.
        Returns True if every record's hash and back-link are intact.
        """
        prev_hash = self.GENESIS_HASH
        for rec in self._audit_chain:
            if rec.prev_hash != prev_hash:
                return False
            expected_hash = self._hash_record(
                rec.index,
                rec.timestamp,
                rec.source_uri,
                rec.target_uri,
                rec.action,
                rec.decision,
                rec.details,
                rec.prev_hash,
            )
            if rec.record_hash != expected_hash:
                return False
            prev_hash = rec.record_hash
        return True

    def _hash_record(
        self,
        index: int,
        timestamp: float,
        source: str,
        target: str,
        action: str,
        decision: AccessDecision,
        details: str,
        prev_hash: str,
    ) -> str:
        payload = f"{index}|{timestamp:.4f}|{source}|{target}|{action}|{str(decision)}|{details}|{prev_hash}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _append_audit_record(
        self,
        source_uri: str,
        target_uri: str,
        action: str,
        decision: AccessDecision,
        details: str,
    ) -> AuditRecord:
        idx = len(self._audit_chain)
        now = time.time()
        prev = self._audit_chain[-1].record_hash if self._audit_chain else self.GENESIS_HASH
        rec_hash = self._hash_record(idx, now, source_uri, target_uri, action, decision, details, prev)

        record = AuditRecord(
            index=idx,
            timestamp=now,
            source_uri=source_uri,
            target_uri=target_uri,
            action=action,
            decision=decision,
            details=details,
            prev_hash=prev,
            record_hash=rec_hash,
        )
        self._audit_chain.append(record)
        return record
