"""Verify a signed, hash-indexed Azure ACL live-evidence manifest offline."""

import argparse
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


REQUIRED_ARTIFACT_IDS = tuple(f"ACL-{number:03d}" for number in range(1, 15))


class ManifestError(ValueError):
    """Raised when an evidence manifest or its referenced evidence is invalid."""


def _load_manifest(path: Path) -> bytes:
    try:
        raw = path.read_bytes()
        manifest = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError("manifest_unreadable_or_invalid_json") from exc
    if not isinstance(manifest, dict):
        raise ManifestError("manifest_root_must_be_object")
    if not isinstance(manifest.get("run_id"), str) or not manifest["run_id"].strip():
        raise ManifestError("invalid_run_id")
    timestamp = manifest.get("generated_at")
    if not isinstance(timestamp, str):
        raise ManifestError("invalid_generated_at")
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ManifestError("invalid_generated_at") from exc
    if parsed_timestamp.tzinfo is None or parsed_timestamp.utcoffset() is None:
        raise ManifestError("generated_at_must_include_timezone")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise ManifestError("artifacts_must_be_array")
    return raw


def _verify_signature(raw_manifest: bytes, signature_path: Path, public_key_path: Path) -> None:
    try:
        public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
        signature = signature_path.read_bytes()
    except (OSError, ValueError) as exc:
        raise ManifestError("signature_or_public_key_unreadable") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise ManifestError("public_key_must_be_ed25519")
    if len(signature) != 64:
        raise ManifestError("invalid_ed25519_signature_length")
    try:
        public_key.verify(signature, raw_manifest)
    except InvalidSignature as exc:
        raise ManifestError("manifest_signature_invalid") from exc


def _safe_artifact_path(root: Path, relative_name: str) -> Path:
    relative = PurePosixPath(relative_name)
    if relative.is_absolute() or not relative.parts or any(part in ("", ".", "..") for part in relative.parts):
        raise ManifestError("unsafe_artifact_path")
    candidate = root.joinpath(*relative.parts)
    try:
        resolved_root = root.resolve(strict=True)
        resolved_candidate = candidate.resolve(strict=True)
        resolved_candidate.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise ManifestError("artifact_path_missing_or_outside_root") from exc
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ManifestError("symlink_artifacts_not_allowed")
    if not resolved_candidate.is_file():
        raise ManifestError("artifact_must_be_regular_file")
    return resolved_candidate


def verify_manifest(
    manifest_path: Path,
    evidence_root: Path,
    signature_path: Path,
    public_key_path: Path,
) -> dict[str, object]:
    raw_manifest = _load_manifest(manifest_path)
    _verify_signature(raw_manifest, signature_path, public_key_path)
    manifest = json.loads(raw_manifest)
    artifacts = manifest["artifacts"]
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    failures: list[str] = []
    verified = 0

    for artifact in artifacts:
        if not isinstance(artifact, dict):
            failures.append("artifact_entry_must_be_object")
            continue
        artifact_id = artifact.get("id")
        relative_name = artifact.get("path")
        expected_digest = artifact.get("sha256")
        if not isinstance(artifact_id, str) or artifact_id not in REQUIRED_ARTIFACT_IDS:
            failures.append("unknown_or_invalid_artifact_id")
            continue
        if artifact_id in seen_ids:
            failures.append(f"duplicate_artifact_id:{artifact_id}")
            continue
        seen_ids.add(artifact_id)
        if not isinstance(relative_name, str) or relative_name in seen_paths:
            failures.append(f"invalid_or_duplicate_path:{artifact_id}")
            continue
        seen_paths.add(relative_name)
        if not isinstance(expected_digest, str) or len(expected_digest) != 64 or any(
            char not in "0123456789abcdef" for char in expected_digest
        ):
            failures.append(f"invalid_sha256:{artifact_id}")
            continue
        try:
            artifact_path = _safe_artifact_path(evidence_root, relative_name)
            actual_digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        except (OSError, ManifestError) as exc:
            failures.append(f"artifact_unavailable:{artifact_id}:{exc}")
            continue
        if actual_digest != expected_digest:
            failures.append(f"digest_mismatch:{artifact_id}")
            continue
        verified += 1

    missing = sorted(set(REQUIRED_ARTIFACT_IDS) - seen_ids)
    failures.extend(f"missing_artifact:{artifact_id}" for artifact_id in missing)
    return {
        "check": "cephas-acl-evidence-manifest",
        "status": "verified" if not failures else "blocked",
        "signature_verified": True,
        "artifacts_verified": verified,
        "required_artifacts": len(REQUIRED_ARTIFACT_IDS),
        "failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify_manifest(args.manifest, args.evidence_root, args.signature, args.public_key)
    except ManifestError as exc:
        result = {
            "check": "cephas-acl-evidence-manifest",
            "status": "blocked",
            "signature_verified": False,
            "failures": [str(exc)],
        }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    sys.exit(main())
