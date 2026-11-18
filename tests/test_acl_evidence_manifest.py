from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.acl_evidence_manifest import REQUIRED_ARTIFACT_IDS, verify_manifest


def create_signed_package(tmp_path: Path):
    root = tmp_path / "evidence"
    root.mkdir()
    artifacts = []
    for artifact_id in REQUIRED_ARTIFACT_IDS:
        name = f"{artifact_id}.txt"
        content = f"synthetic evidence fixture for {artifact_id}".encode()
        (root / name).write_bytes(content)
        artifacts.append(
            {"id": artifact_id, "path": name, "sha256": hashlib.sha256(content).hexdigest()}
        )
    manifest = {
        "run_id": "test-run-001",
        "generated_at": "2026-11-18T10:00:00Z",
        "artifacts": artifacts,
    }
    manifest_path = tmp_path / "manifest.json"
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest_path.write_bytes(raw)
    private_key = Ed25519PrivateKey.generate()
    public_key_path = tmp_path / "public.pem"
    public_key_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    signature_path = tmp_path / "manifest.sig"
    signature_path.write_bytes(private_key.sign(raw))
    return root, manifest_path, signature_path, public_key_path, manifest


def test_verifies_complete_signed_manifest_and_all_hashes(tmp_path):
    root, manifest, signature, public_key, _ = create_signed_package(tmp_path)
    result = verify_manifest(manifest, root, signature, public_key)
    assert result["status"] == "verified"
    assert result["artifacts_verified"] == 14
    assert result["failures"] == []


def test_rejects_manifest_tampering_after_signing(tmp_path):
    root, manifest_path, signature, public_key, manifest = create_signed_package(tmp_path)
    manifest["run_id"] = "tampered"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="manifest_signature_invalid"):
        verify_manifest(manifest_path, root, signature, public_key)


def test_rejects_artifact_content_tampering(tmp_path):
    root, manifest, signature, public_key, _ = create_signed_package(tmp_path)
    (root / "ACL-001.txt").write_text("changed", encoding="utf-8")
    result = verify_manifest(manifest, root, signature, public_key)
    assert result["status"] == "blocked"
    assert "digest_mismatch:ACL-001" in result["failures"]


def test_rejects_missing_required_artifact(tmp_path):
    root, manifest_path, signature, public_key, data = create_signed_package(tmp_path)
    data["artifacts"] = data["artifacts"][1:]
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    manifest_path.write_bytes(raw)
    private = Ed25519PrivateKey.generate()
    # Re-sign with the matching test key by replacing the public key and signature.
    public_key.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    signature.write_bytes(private.sign(raw))
    result = verify_manifest(manifest_path, root, signature, public_key)
    assert result["status"] == "blocked"
    assert "missing_artifact:ACL-001" in result["failures"]


def test_rejects_path_traversal(tmp_path):
    root, manifest_path, signature, public_key, data = create_signed_package(tmp_path)
    data["artifacts"][0]["path"] = "../outside.txt"
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    manifest_path.write_bytes(raw)
    private = Ed25519PrivateKey.generate()
    public_key.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    signature.write_bytes(private.sign(raw))
    result = verify_manifest(manifest_path, root, signature, public_key)
    assert result["status"] == "blocked"
    assert any("artifact_unavailable:ACL-001" in item for item in result["failures"])


def test_rejects_symlink_artifact(tmp_path):
    root, manifest_path, signature, public_key, data = create_signed_package(tmp_path)
    target = tmp_path / "external.txt"
    target.write_text("external", encoding="utf-8")
    (root / "ACL-001.txt").unlink()
    (root / "ACL-001.txt").symlink_to(target)
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    manifest_path.write_bytes(raw)
    private = Ed25519PrivateKey.generate()
    public_key.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    signature.write_bytes(private.sign(raw))
    result = verify_manifest(manifest_path, root, signature, public_key)
    assert result["status"] == "blocked"
    assert any("artifact_unavailable:ACL-001" in item for item in result["failures"])
