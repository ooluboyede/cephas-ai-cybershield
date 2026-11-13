from datetime import datetime, timezone

import pytest

from cybershield_ml.dircm_identity import (
    IdentityAssurance, IdentifierType, ResolutionStatus,
    SourceTrustContext, digest_device_identifier, new_device_id, resolve_device_identity,
)


class FakeRegistry:
    def __init__(self):
        self.verified = {}
        self.candidates = []

    def get_or_create_verified_device(self, *, tenant_id, source_id, identifier_type, identifier_digest):
        key = (tenant_id, source_id, identifier_type, identifier_digest)
        return self.verified.setdefault(key, new_device_id())

    def create_match_candidate(self, *, tenant_id, source_id, identifier_type, identifier_digest, observed_at):
        candidate_id = f"candidate-{len(self.candidates) + 1}"
        self.candidates.append((tenant_id, source_id, identifier_type, identifier_digest, observed_at))
        return candidate_id


NOW = datetime(2026, 11, 13, 8, 0, tzinfo=timezone.utc)
KEY = b"k" * 32


def test_verified_certificate_resolves_stable_opaque_device_id():
    registry = FakeRegistry()
    source = SourceTrustContext("tenant-a", "edr-a", IdentityAssurance.CRYPTOGRAPHICALLY_VERIFIED, True)
    first = resolve_device_identity(
        source=source, identifier_type=IdentifierType.DEVICE_CERTIFICATE,
        identifier_value="certificate-123", observed_at=NOW, tenant_key=KEY, registry=registry,
    )
    second = resolve_device_identity(
        source=source, identifier_type=IdentifierType.DEVICE_CERTIFICATE,
        identifier_value="certificate-123", observed_at=NOW, tenant_key=KEY, registry=registry,
    )
    assert first.status == ResolutionStatus.VERIFIED_DEVICE
    assert first.device_id == second.device_id
    assert first.device_id != "certificate-123"
    assert first.candidate_id is None


def test_tenant_scoped_hmac_prevents_cross_tenant_identifier_linking():
    digest_a = digest_device_identifier(
        tenant_id="tenant-a", source_id="edr", identifier_type=IdentifierType.MANAGED_AGENT_ID,
        identifier_value="same-id", tenant_key=KEY,
    )
    digest_b = digest_device_identifier(
        tenant_id="tenant-b", source_id="edr", identifier_type=IdentifierType.MANAGED_AGENT_ID,
        identifier_value="same-id", tenant_key=KEY,
    )
    assert digest_a != digest_b


def test_probabilistic_signal_creates_candidate_without_device_merge():
    registry = FakeRegistry()
    source = SourceTrustContext("tenant-a", "network-sensor", IdentityAssurance.PROBABILISTIC, True)
    result = resolve_device_identity(
        source=source, identifier_type=IdentifierType.PROBABILISTIC_SIGNAL,
        identifier_value="weak-fingerprint", observed_at=NOW, tenant_key=KEY, registry=registry,
    )
    assert result.status == ResolutionStatus.MATCH_CANDIDATE
    assert result.device_id is None
    assert result.candidate_id == "candidate-1"
    assert len(registry.verified) == 0
    assert len(registry.candidates) == 1


def test_unauthenticated_source_is_rejected():
    with pytest.raises(ValueError, match="authenticated registered source"):
        SourceTrustContext("tenant-a", "spoofed-source", IdentityAssurance.AUTHENTICATED_MANAGED, False)


def test_source_cannot_claim_stronger_identifier_than_its_assurance():
    registry = FakeRegistry()
    source = SourceTrustContext("tenant-a", "managed-agent", IdentityAssurance.AUTHENTICATED_MANAGED, True)
    with pytest.raises(ValueError, match="not permitted"):
        resolve_device_identity(
            source=source, identifier_type=IdentifierType.DEVICE_CERTIFICATE,
            identifier_value="forged-cert", observed_at=NOW, tenant_key=KEY, registry=registry,
        )
    assert not registry.verified


def test_unknown_source_never_creates_verified_device():
    registry = FakeRegistry()
    source = SourceTrustContext("tenant-a", "unknown-source", IdentityAssurance.UNKNOWN, True)
    result = resolve_device_identity(
        source=source, identifier_type=IdentifierType.PROBABILISTIC_SIGNAL,
        identifier_value="some-signal", observed_at=NOW, tenant_key=KEY, registry=registry,
    )
    assert result.status == ResolutionStatus.UNKNOWN
    assert result.device_id is None
    assert result.candidate_id is None
    assert not registry.verified
    assert not registry.candidates


def test_naive_observation_timestamp_is_rejected():
    registry = FakeRegistry()
    source = SourceTrustContext("tenant-a", "edr-a", IdentityAssurance.CRYPTOGRAPHICALLY_VERIFIED, True)
    with pytest.raises(ValueError, match="timezone"):
        resolve_device_identity(
            source=source, identifier_type=IdentifierType.DEVICE_CERTIFICATE,
            identifier_value="certificate-123", observed_at=datetime(2026, 11, 13),
            tenant_key=KEY, registry=registry,
        )


def test_tenant_key_minimum_length_is_enforced():
    with pytest.raises(ValueError, match="at least 32 bytes"):
        digest_device_identifier(
            tenant_id="tenant-a", source_id="edr", identifier_type=IdentifierType.DEVICE_CERTIFICATE,
            identifier_value="certificate-123", tenant_key=b"short",
        )
