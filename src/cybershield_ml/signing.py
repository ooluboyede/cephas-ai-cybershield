"""Ed25519 signing and verification for CyberShield model releases."""
import base64
import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SIGNATURE_FILE = "model_signature.json"
SIGNATURE_SCHEMA_VERSION = "1.0.0"
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _signed_payload(directory: Path, metadata: dict) -> bytes:
    metadata_path = directory / "model_metadata.json"
    artifact_path = directory / "isolation_forest.joblib"
    if metadata_path.is_symlink() or not metadata_path.is_file():
        raise ValueError("model metadata must be a regular, non-symlink file")
    if artifact_path.is_symlink() or not artifact_path.is_file():
        raise ValueError("model artifact must be a regular, non-symlink file")
    artifact_hash = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    if artifact_hash != metadata.get("artifact_sha256"):
        raise ValueError("model artifact SHA-256 verification failed")
    payload = {
        "product": metadata["product"],
        "version": metadata["version"],
        "metadata_schema_version": metadata["metadata_schema_version"],
        "feature_schema_version": metadata["feature_schema_version"],
        "algorithm": metadata["algorithm"],
        "tenant_id": metadata["tenant_id"],
        "training_scope": metadata["training_scope"],
        "release_sequence": metadata["release_sequence"],\n        "deployment_id": metadata["deployment_id"],
        "metadata_sha256": hashlib.sha256(metadata_path.read_bytes()).hexdigest(),
        "artifact_sha256": artifact_hash,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_model(
    directory: str | Path,
    tenant_id: str,
    private_key_pem: bytes | str,
    key_id: str,
    password: bytes | None = None,
) -> dict:
    """Sign model bytes and metadata with an externally managed Ed25519 private key."""
    if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
        raise ValueError("key_id must be 1-128 safe identifier characters")
    path = Path(directory)
    metadata_path = path / "model_metadata.json"
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("model metadata is unreadable or invalid JSON") from exc
    if not isinstance(metadata, dict) or metadata.get("tenant_id") != tenant_id:
        raise ValueError("model metadata does not match the requested tenant scope")
    key_bytes = private_key_pem.encode("utf-8") if isinstance(private_key_pem, str) else private_key_pem
    try:
        private_key = serialization.load_pem_private_key(key_bytes, password=password)
    except (TypeError, ValueError) as exc:
        raise ValueError("publisher private key PEM is invalid or password is incorrect") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("publisher private key must use Ed25519")
    signature = private_key.sign(_signed_payload(path, metadata))
    document = {
        "signature_schema_version": SIGNATURE_SCHEMA_VERSION,
        "algorithm": "Ed25519",
        "key_id": key_id,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    target = path / SIGNATURE_FILE
    if target.is_symlink():
        raise ValueError("model signature file must not be a symlink")
    temporary = path / f".{SIGNATURE_FILE}.tmp"
    temporary.write_text(json.dumps(document, indent=2), encoding="utf-8")
    temporary.replace(target)
    return document


def verify_model_signature(
    directory: str | Path,
    metadata: dict,
    trusted_public_keys: Mapping[str, bytes | str],
) -> str:
    """Verify signature using a customer-provisioned publisher public-key allowlist."""
    if not trusted_public_keys:
        raise ValueError("a trusted publisher public-key ring is required")
    path = Path(directory)
    signature_path = path / SIGNATURE_FILE
    if signature_path.is_symlink() or not signature_path.is_file():
        raise ValueError("a regular, non-symlink publisher signature file is required")
    try:
        document = json.loads(signature_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("publisher signature document is unreadable or invalid JSON") from exc
    if not isinstance(document, dict):
        raise TypeError("publisher signature document must be a JSON object")
    if document.get("signature_schema_version") != SIGNATURE_SCHEMA_VERSION:
        raise ValueError("publisher signature schema version is incompatible")
    if document.get("algorithm") != "Ed25519":
        raise ValueError("publisher signature algorithm is not supported")
    key_id = document.get("key_id")
    if not isinstance(key_id, str) or key_id not in trusted_public_keys:
        raise ValueError("publisher signing key is not trusted")
    try:
        signature = base64.b64decode(document["signature"], validate=True)
        pem = trusted_public_keys[key_id]
        pem_bytes = pem.encode("utf-8") if isinstance(pem, str) else pem
        public_key = serialization.load_pem_public_key(pem_bytes)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("publisher signature or trusted public key is invalid") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("trusted publisher key must use Ed25519")
    try:
        public_key.verify(signature, _signed_payload(path, metadata))
    except InvalidSignature as exc:
        raise ValueError("publisher signature verification failed") from exc
    return key_id
