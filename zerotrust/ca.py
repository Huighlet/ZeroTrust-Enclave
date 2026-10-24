"""
ZeroTrust-Enclave: Ephemeral Certificate Authority (CA).
Mints and cryptographically validates short-lived SPIFFE Verifiable Identity Documents (SVIDs).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from typing import Dict, Optional, Set

from zerotrust.types import (
    SpiffeID,
    SVIDExpiredError,
    SVIDRevokedError,
    SVIDToken,
    WorkloadProfile,
    ZeroTrustSecurityError,
)


class EphemeralCertificateAuthority:
    """
    In-memory micro-CA issuing short-lived cryptographically signed SVID tokens.
    Guarantees strict zero-trust credential rotation, cryptographic authenticity,
    and fast-path revocation.
    """

    def __init__(
        self,
        trust_domain: str,
        signing_key: Optional[bytes] = None,
        default_ttl_seconds: float = 3600.0,
    ) -> None:
        self.trust_domain = trust_domain
        self._signing_key: bytes = signing_key if signing_key else secrets.token_bytes(32)
        self.default_ttl_seconds = default_ttl_seconds

        # Revocation list (set of serial numbers)
        self._revoked_serials: Set[str] = set()

        # Issued tokens registry: serial_number -> SVIDToken
        self._issued_tokens: Dict[str, SVIDToken] = {}

    def _sign_payload(self, serial: str, uri: str, issued_at: float, expires_at: float) -> str:
        """Create deterministic HMAC-SHA256 signature for token fields."""
        payload = f"{serial}|{uri}|{issued_at:.4f}|{expires_at:.4f}".encode("utf-8")
        return hmac.new(self._signing_key, payload, hashlib.sha256).hexdigest()

    def issue_svid(
        self,
        profile_or_id: WorkloadProfile | SpiffeID,
        ttl_seconds: Optional[float] = None,
    ) -> SVIDToken:
        """
        Mint a new short-lived SVID token for an attested workload.
        """
        spiffe_id = profile_or_id.spiffe_id if isinstance(profile_or_id, WorkloadProfile) else profile_or_id

        if spiffe_id.trust_domain != self.trust_domain:
            raise ZeroTrustSecurityError(
                f"Cannot issue SVID: workload trust domain '{spiffe_id.trust_domain}' "
                f"does not match CA trust domain '{self.trust_domain}'"
            )

        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        now = time.time()
        expires = now + ttl
        serial = f"svid-{secrets.token_hex(12)}"

        signature = self._sign_payload(serial, spiffe_id.uri, now, expires)

        token = SVIDToken(
            serial_number=serial,
            spiffe_id=spiffe_id,
            issued_at=now,
            expires_at=expires,
            signature=signature,
            is_revoked=False,
        )

        self._issued_tokens[serial] = token
        return token

    def verify_svid(self, token: SVIDToken) -> bool:
        """
        Validate an SVID token's cryptographic integrity, expiration, and revocation status.

        Raises:
            SVIDRevokedError: If the token has been marked revoked.
            SVIDExpiredError: If the token TTL has elapsed.
            ZeroTrustSecurityError: If cryptographic signature is forged or invalid.
        """
        if token.serial_number in self._revoked_serials or token.is_revoked:
            raise SVIDRevokedError(f"SVID token '{token.serial_number}' has been revoked.")

        now = time.time()
        if now > token.expires_at:
            raise SVIDExpiredError(
                f"SVID token '{token.serial_number}' expired at {token.expires_at:.2f} (current: {now:.2f})."
            )

        # Constant-time cryptographic verification
        expected_sig = self._sign_payload(
            token.serial_number, token.spiffe_id.uri, token.issued_at, token.expires_at
        )

        if not hmac.compare_digest(expected_sig, token.signature):
            raise ZeroTrustSecurityError(
                f"Cryptographic signature validation failed for SVID '{token.serial_number}'."
            )

        return True

    def revoke_svid(self, serial_number: str) -> None:
        """Revoke an active SVID token immediately."""
        self._revoked_serials.add(serial_number)
        if serial_number in self._issued_tokens:
            self._issued_tokens[serial_number].is_revoked = True

    def is_revoked(self, serial_number: str) -> bool:
        """Check if a serial number is revoked."""
        return serial_number in self._revoked_serials

    def count_active_svids(self) -> int:
        """Count currently valid, unexpired, non-revoked issued tokens."""
        now = time.time()
        return sum(
            1 for t in self._issued_tokens.values()
            if not t.is_revoked and t.serial_number not in self._revoked_serials and now <= t.expires_at
        )
