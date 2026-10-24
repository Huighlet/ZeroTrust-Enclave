"""
ZeroTrust Client SDK: Idiomatic high-performance client for the ZeroTrust-Enclave Attestation & PEP Gateway.
Supports SPIFFE RFC 3986 workload attestation, ephemeral SVID token minting, ABAC policy authorization, and audit export.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional, Union

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore


class ZeroTrustClient:
    """
    Client for interacting with a live ZeroTrust-Enclave Policy Enforcement Point (PEP).
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8443",
        api_key: Optional[str] = None,
        timeout_seconds: float = 10.0,
        http_client: Optional[Any] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        if http_client is not None:
            self._client = http_client
        elif httpx is not None:
            self._client = httpx.Client(
                base_url=self.base_url,
                headers=headers,
                timeout=self.timeout_seconds,
            )
        else:
            self._client = None

    def close(self) -> None:
        if self._client is not None:
            self._client.close()

    def __enter__(self) -> ZeroTrustClient:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def register_workload(
        self,
        profile_id: str,
        spiffe_uri: str,
        expected_binary_sha256: str,
        expected_image_path: str,
        environment: str = "prod",
        attributes: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Register approved workload identity profile."""
        payload = {
            "profile_id": profile_id,
            "spiffe_uri": spiffe_uri,
            "expected_binary_sha256": expected_binary_sha256,
            "expected_image_path": expected_image_path,
            "environment": environment,
            "attributes": attributes or {},
        }
        resp = self._client.post("/v1/workloads", json=payload)
        resp.raise_for_status()
        return resp.json()

    def attest_workload(
        self,
        profile_id: str,
        candidate_bytes_or_hex: Union[bytes, str],
        environment: str = "prod",
        ttl_seconds: float = 3600.0,
    ) -> Dict[str, Any]:
        """Submit candidate binary bytes for cryptographic attestation and receive signed SVID token."""
        cand_hex = candidate_bytes_or_hex.hex() if isinstance(candidate_bytes_or_hex, bytes) else candidate_bytes_or_hex
        payload = {
            "profile_id": profile_id,
            "candidate_hex": cand_hex,
            "environment": environment,
            "ttl_seconds": ttl_seconds,
        }
        resp = self._client.post("/v1/attest", json=payload)
        resp.raise_for_status()
        return resp.json()

    def authorize(
        self,
        svid_serial: str,
        target_spiffe_uri: str,
        action: str,
        client_attributes: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Evaluate access request at Policy Enforcement Point (PEP)."""
        payload = {
            "svid_serial": svid_serial,
            "target_spiffe_uri": target_spiffe_uri,
            "action": action,
            "client_attributes": client_attributes or {},
        }
        resp = self._client.post("/v1/authorize", json=payload)
        resp.raise_for_status()
        return resp.json()

    def add_policy_rule(
        self,
        rule_id: str,
        source_pattern: str,
        target_pattern: str,
        allowed_actions: List[str],
        required_attributes: Optional[Dict[str, str]] = None,
        description: str = "",
    ) -> Dict[str, Any]:
        """Register ABAC microsegmentation rule."""
        payload = {
            "rule_id": rule_id,
            "source_pattern": source_pattern,
            "target_pattern": target_pattern,
            "allowed_actions": allowed_actions,
            "required_attributes": required_attributes or {},
            "description": description,
        }
        resp = self._client.post("/v1/policies", json=payload)
        resp.raise_for_status()
        return resp.json()

    def revoke_svid(self, serial: str) -> Dict[str, Any]:
        """Emergency revocation of an active SVID credential."""
        resp = self._client.post(f"/v1/svid/revoke/{serial}")
        resp.raise_for_status()
        return resp.json()

    def export_audit_chain(self) -> Dict[str, Any]:
        """Export verifiable cryptographic audit chain."""
        resp = self._client.get("/v1/audit/chain")
        resp.raise_for_status()
        return resp.json()

    def get_metrics(self) -> str:
        """Fetch Prometheus metrics."""
        resp = self._client.get("/metrics")
        resp.raise_for_status()
        return resp.text
