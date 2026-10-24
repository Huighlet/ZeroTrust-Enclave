"""
ZeroTrust-Enclave: Cryptographic Workload Attestation Engine.
Verifies binary integrity, executable digests, and runtime metadata before issuing trust.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Dict, Optional

from zerotrust.types import (
    AttestationFailedError,
    SpiffeID,
    WorkloadProfile,
)


class WorkloadAttestationEngine:
    """
    Evaluates workload identity against pre-registered ground-truth profiles.
    Verifies SHA-256 cryptographic image digest and execution environment invariants.
    """

    def __init__(self) -> None:
        self._profiles: Dict[str, WorkloadProfile] = {}
        # Secondary index by SPIFFE ID URI for fast lookup
        self._by_spiffe_uri: Dict[str, WorkloadProfile] = {}

    def register_profile(self, profile: WorkloadProfile) -> None:
        """Register an authorized workload profile."""
        self._profiles[profile.profile_id] = profile
        self._by_spiffe_uri[profile.spiffe_id.uri] = profile

    def get_profile(self, profile_id: str) -> Optional[WorkloadProfile]:
        """Retrieve profile by unique profile identifier."""
        return self._profiles.get(profile_id)

    def get_profile_by_spiffe_id(self, spiffe_id: SpiffeID) -> Optional[WorkloadProfile]:
        """Retrieve profile by SPIFFE ID."""
        return self._by_spiffe_uri.get(spiffe_id.uri)

    @staticmethod
    def compute_sha256(data_or_path: bytes | str | Path) -> str:
        """Compute SHA-256 digest of raw bytes or file path."""
        hasher = hashlib.sha256()
        if isinstance(data_or_path, (bytes, bytearray, memoryview)):
            hasher.update(data_or_path)
            return hasher.hexdigest()

        path = Path(data_or_path)
        if not path.is_file():
            raise FileNotFoundError(f"Binary target not found: {path}")

        with path.open("rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def attest_workload(
        self,
        candidate_bytes: Optional[bytes] = None,
        candidate_path: Optional[str | Path] = None,
        spiffe_id: Optional[SpiffeID] = None,
        profile_id: Optional[str] = None,
        environment: str = "prod",
    ) -> WorkloadProfile:
        """
        Attest a workload binary against approved profiles.

        Raises:
            AttestationFailedError: If hash mismatch, missing profile, or environment violation.
        """
        if candidate_bytes is None and candidate_path is None:
            raise AttestationFailedError("Attestation requires either binary bytes or file path.")

        # Find matching profile candidate
        profile: Optional[WorkloadProfile] = None
        if profile_id:
            profile = self._profiles.get(profile_id)
            if not profile:
                raise AttestationFailedError(f"No workload profile registered with ID: '{profile_id}'")
        elif spiffe_id:
            profile = self._by_spiffe_uri.get(spiffe_id.uri)
            if not profile:
                raise AttestationFailedError(f"No workload profile registered for SPIFFE ID: '{spiffe_id.uri}'")
        else:
            raise AttestationFailedError("Attestation requires profile_id or spiffe_id selector.")

        # Verify environment match
        if profile.environment != environment:
            raise AttestationFailedError(
                f"Environment mismatch: profile expects '{profile.environment}', got '{environment}'."
            )

        # Compute candidate digest
        computed_digest = self.compute_sha256(candidate_bytes if candidate_bytes is not None else candidate_path)

        # Cryptographic verification against ground-truth
        if computed_digest.lower() != profile.expected_binary_sha256.lower():
            raise AttestationFailedError(
                f"Binary digest verification failed for {profile.spiffe_id.uri}. "
                f"Expected: {profile.expected_binary_sha256}, Computed: {computed_digest}"
            )

        # Path verification if candidate_path provided
        if candidate_path is not None:
            norm_candidate = str(Path(candidate_path).resolve())
            norm_expected = str(Path(profile.expected_image_path).resolve())
            if norm_candidate.lower() != norm_expected.lower():
                raise AttestationFailedError(
                    f"Binary path mismatch: expected '{norm_expected}', got '{norm_candidate}'"
                )

        return profile
