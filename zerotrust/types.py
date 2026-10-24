"""
ZeroTrust-Enclave: SPIFFE Standard Types, Workload Profiles, and SVID Token Definitions.
"""

from __future__ import annotations

import dataclasses
import enum
import time
import urllib.parse
from typing import Any, Dict, Optional


class AccessDecision(enum.StrEnum):
    """Microsegmentation authorization decision."""
    ALLOW = "ALLOW"
    DENY = "DENY"


@dataclasses.dataclass(slots=True, frozen=True)
class SpiffeID:
    """
    Standardized SPIFFE URI Representation (RFC 3986).
    Format: spiffe://<trust_domain>/<path>
    """
    trust_domain: str
    path: str

    def __post_init__(self) -> None:
        if not self.trust_domain:
            raise ValueError("SPIFFE ID requires a non-empty trust domain.")
        if not self.path.startswith("/"):
            raise ValueError(f"SPIFFE ID path must begin with '/', got '{self.path}'")

    @classmethod
    def parse(cls, uri_string: str) -> SpiffeID:
        """Parse standard SPIFFE URI string."""
        parsed = urllib.parse.urlparse(uri_string)
        if parsed.scheme != "spiffe":
            raise ValueError(f"Invalid SPIFFE scheme: expected 'spiffe://', got '{parsed.scheme}://'")
        if not parsed.netloc:
            raise ValueError(f"Missing trust domain in SPIFFE URI: '{uri_string}'")
        return cls(trust_domain=parsed.netloc, path=parsed.path)

    @property
    def uri(self) -> str:
        return f"spiffe://{self.trust_domain}{self.path}"

    def __str__(self) -> str:
        return self.uri


@dataclasses.dataclass(slots=True, frozen=True)
class WorkloadProfile:
    """Registered ground-truth identity profile of an approved service binary."""
    profile_id: str
    spiffe_id: SpiffeID
    expected_binary_sha256: str
    expected_image_path: str
    environment: str = "prod"
    attributes: Dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(slots=True)
class SVIDToken:
    """
    SPIFFE Verifiable Identity Document (SVID) Credential.
    Short-lived cryptographic token issued by Ephemeral CA upon successful attestation.
    """
    serial_number: str
    spiffe_id: SpiffeID
    issued_at: float
    expires_at: float
    signature: str
    is_revoked: bool = False

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def is_valid(self) -> bool:
        return (not self.is_revoked) and (not self.is_expired)


@dataclasses.dataclass(slots=True, frozen=True)
class AuthContext:
    """Invocation context for microsegmentation policy evaluation."""
    source_spiffe_id: SpiffeID
    target_spiffe_id: SpiffeID
    action: str
    environment: str = "prod"
    client_attributes: Dict[str, str] = dataclasses.field(default_factory=dict)


# -------------------------------------------------------------------------
# Exceptions
# -------------------------------------------------------------------------

class ZeroTrustSecurityError(Exception):
    """Base exception for all ZeroTrust-Enclave security violations."""


class AttestationFailedError(ZeroTrustSecurityError):
    """Raised when workload fails cryptographic binary verification or profile mismatch."""


class AccessDeniedError(ZeroTrustSecurityError):
    """Raised when microsegmentation policy denies access (Default Deny)."""


class SVIDExpiredError(ZeroTrustSecurityError):
    """Raised when attempting to use an expired SVID token past its TTL."""


class SVIDRevokedError(ZeroTrustSecurityError):
    """Raised when an SVID token has been revoked by the security authority."""
