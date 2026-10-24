"""
Tests for Workload Attestation Engine.
"""

import hashlib
from pathlib import Path
import pytest
from zerotrust.attestation import WorkloadAttestationEngine
from zerotrust.types import AttestationFailedError, SpiffeID, WorkloadProfile


@pytest.fixture
def sample_binary(tmp_path: Path) -> tuple[Path, bytes, str]:
    content = b"MACHINE_CODE_EXECUTABLE_PAYLOAD_V1"
    bin_path = tmp_path / "service_bin"
    bin_path.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    return bin_path, content, digest


@pytest.fixture
def engine(sample_binary) -> tuple[WorkloadAttestationEngine, WorkloadProfile]:
    bin_path, content, digest = sample_binary
    eng = WorkloadAttestationEngine()
    spiffe = SpiffeID.parse("spiffe://cluster.local/ns/billing/service/invoice")
    prof = WorkloadProfile(
        profile_id="invoice-worker-prod",
        spiffe_id=spiffe,
        expected_binary_sha256=digest,
        expected_image_path=str(bin_path),
        environment="prod",
    )
    eng.register_profile(prof)
    return eng, prof


def test_attestation_success_with_bytes(engine, sample_binary):
    eng, prof = engine
    _, content, _ = sample_binary
    verified = eng.attest_workload(candidate_bytes=content, profile_id="invoice-worker-prod")
    assert verified.profile_id == "invoice-worker-prod"


def test_attestation_success_with_path(engine, sample_binary):
    eng, prof = engine
    bin_path, _, _ = sample_binary
    verified = eng.attest_workload(candidate_path=bin_path, spiffe_id=prof.spiffe_id)
    assert verified.profile_id == "invoice-worker-prod"


def test_attestation_tampered_binary_rejected(engine):
    eng, prof = engine
    tampered = b"CORRUPTED_TAMPERED_MACHINE_CODE"
    with pytest.raises(AttestationFailedError, match="Binary digest verification failed"):
        eng.attest_workload(candidate_bytes=tampered, profile_id="invoice-worker-prod")


def test_attestation_unregistered_profile(engine, sample_binary):
    eng, prof = engine
    _, content, _ = sample_binary
    with pytest.raises(AttestationFailedError, match="No workload profile registered"):
        eng.attest_workload(candidate_bytes=content, profile_id="non-existent")


def test_attestation_environment_mismatch(engine, sample_binary):
    eng, prof = engine
    _, content, _ = sample_binary
    with pytest.raises(AttestationFailedError, match="Environment mismatch"):
        eng.attest_workload(
            candidate_bytes=content,
            profile_id="invoice-worker-prod",
            environment="staging",
        )
