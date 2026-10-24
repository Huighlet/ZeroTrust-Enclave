"""
ZeroTrust-Enclave: SPIFFE Workload Attestation, Ephemeral mTLS CA & Microsegmentation Gateway.
"""

from zerotrust.attestation import WorkloadAttestationEngine
from zerotrust.ca import EphemeralCertificateAuthority
from zerotrust.gateway import AuditRecord, ZeroTrustGateway
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

__version__ = "1.0.0"

__all__ = [
    "AccessDecision",
    "AccessDeniedError",
    "AttestationFailedError",
    "AuditRecord",
    "AuthContext",
    "EphemeralCertificateAuthority",
    "MicrosegmentationPolicyEngine",
    "PolicyRule",
    "SpiffeID",
    "SVIDExpiredError",
    "SVIDRevokedError",
    "SVIDToken",
    "WorkloadAttestationEngine",
    "WorkloadProfile",
    "ZeroTrustGateway",
    "ZeroTrustSecurityError",
]
