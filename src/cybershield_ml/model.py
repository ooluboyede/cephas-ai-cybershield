import hashlib
import json
import re
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from . import FEATURE_SCHEMA_VERSION, MODEL_METADATA_SCHEMA_VERSION, __version__
from .features import FEATURE_COLUMNS
from .release_state import ReleaseStateStore
from .signing import verify_model_signature

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_METADATA_FIELDS = {
    "product", "version", "metadata_schema_version", "feature_schema_version",
    "algorithm", "tenant_id", "training_scope", "features", "training_rows",
    "dataset_sha256", "artifact_sha256", "release_sequence", "deployment_id", "parameters", "warning",
}


def validate_feature_frame(features: pd.DataFrame) -> None:
    missing = set(FEATURE_COLUMNS) - set(features.columns)
    if missing:
        raise ValueError(f"missing features: {sorted(missing)}")
    values = features[FEATURE_COLUMNS]
    if not all(pd.api.types.is_numeric_dtype(values[column]) for column in FEATURE_COLUMNS):
        raise ValueError("all model features must be numeric")
    matrix = values.to_numpy(dtype=float)
    if not np.isfinite(matrix).all():
        raise ValueError("model features must contain only finite values")
    if (matrix < 0).any():
        raise ValueError("model features cannot be negative")


def fingerprint(features: pd.DataFrame) -> str:
    validate_feature_frame(features)
    canonical = features[FEATURE_COLUMNS].to_csv(index=False, float_format="%.12g")
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def train_model(
    features: pd.DataFrame,
    tenant_id: str,
    contamination: float = 0.02,
    seed: int = 42,
):
    if not tenant_id or not tenant_id.strip():
        raise ValueError("tenant_id is required")
    if "tenant_id" not in features.columns:
        raise ValueError("tenant_id column is required for tenant-scoped training")
    if not 0 < contamination <= 0.5:
        raise ValueError("contamination must be in (0, 0.5]")
    tenant_features = features.loc[features["tenant_id"] == tenant_id].copy()
    if tenant_features.empty:
        raise ValueError(f"no training rows found for tenant {tenant_id!r}")
    if len(tenant_features) < 2:
        raise ValueError("at least two tenant-scoped feature rows are required")
    validate_feature_frame(tenant_features)
    model = IsolationForest(
        n_estimators=200, contamination=contamination, random_state=seed, n_jobs=-1
    )
    model.fit(tenant_features[FEATURE_COLUMNS])
    model.cephas_tenant_id_ = tenant_id
    model.cephas_dataset_sha256_ = fingerprint(tenant_features)
    return model


def score(model, features: pd.DataFrame) -> pd.DataFrame:
    tenant_id = getattr(model, "cephas_tenant_id_", None)
    if not tenant_id:
        raise ValueError("model has no verified CEPHAS tenant scope")
    if "tenant_id" not in features.columns:
        raise ValueError("tenant_id column is required for tenant-scoped scoring")
    if not features.empty and not features["tenant_id"].eq(tenant_id).all():
        raise ValueError("scoring data contains rows outside the model tenant scope")
    validate_feature_frame(features)
    result = features.copy()
    if result.empty:
        result["anomaly_score"] = pd.Series(dtype=float)
        result["anomaly_flag"] = pd.Series(dtype=int)
        return result
    result["anomaly_score"] = model.decision_function(result[FEATURE_COLUMNS])
    result["anomaly_flag"] = (model.predict(result[FEATURE_COLUMNS]) == -1).astype(int)
    return result


def save_model(
    model, features: pd.DataFrame, directory: str | Path, release_sequence: int = 1, deployment_id: str = "default"
):
    tenant_id = getattr(model, "cephas_tenant_id_", None)
    if not tenant_id:
        raise ValueError("refusing to save a model without verified tenant scope")
    if isinstance(release_sequence, bool) or not isinstance(release_sequence, int) or release_sequence < 1:
        raise ValueError("release_sequence must be a positive integer")
    if "tenant_id" not in features.columns or (
        not features.empty and not features["tenant_id"].eq(tenant_id).all()
    ):
        raise ValueError("model artifact data does not match the model tenant scope")
    validate_feature_frame(features)
    dataset_sha256 = fingerprint(features)
    trained_dataset_sha256 = getattr(model, "cephas_dataset_sha256_", None)
    if not trained_dataset_sha256 or dataset_sha256 != trained_dataset_sha256:
        raise ValueError("artifact dataset does not match the model training dataset")
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    artifact_path = path / "isolation_forest.joblib"
    joblib.dump(model, artifact_path)
    artifact_sha256 = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    metadata = {
        "product": "CEPHAS AI CyberShield",
        "version": __version__,
        "metadata_schema_version": MODEL_METADATA_SCHEMA_VERSION,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "algorithm": "IsolationForest",
        "tenant_id": tenant_id,
        "training_scope": "single_tenant",
        "features": FEATURE_COLUMNS,
        "training_rows": len(features),
        "dataset_sha256": dataset_sha256,
        "artifact_sha256": artifact_sha256,
        "release_sequence": release_sequence,
        "deployment_id": deployment_id,
        "parameters": model.get_params(),
        "warning": "Anomaly is not proof of malicious activity; analyst review required.",
    }
    metadata_path = path / "model_metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2, default=str), encoding="utf-8")
    return metadata


def _read_and_validate_metadata(metadata_path: Path, tenant_id: str) -> dict:
    if metadata_path.is_symlink() or not metadata_path.is_file():
        raise ValueError("model metadata must be a regular, non-symlink file")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("model metadata is unreadable or invalid JSON") from exc
    if not isinstance(metadata, dict):
        raise ValueError("model metadata must be a JSON object")  # noqa: TRY004
    missing = _REQUIRED_METADATA_FIELDS - metadata.keys()
    if missing:
        raise ValueError(f"model metadata is missing fields: {sorted(missing)}")
    if metadata["product"] != "CEPHAS AI CyberShield":
        raise ValueError("model metadata product is not recognised")
    if metadata["version"] != __version__:
        raise ValueError("model version is incompatible with this CyberShield release")
    if metadata["metadata_schema_version"] != MODEL_METADATA_SCHEMA_VERSION:
        raise ValueError("model metadata schema version is incompatible")
    if metadata["feature_schema_version"] != FEATURE_SCHEMA_VERSION:
        raise ValueError("model feature schema version is incompatible")
    if metadata["algorithm"] != "IsolationForest":
        raise ValueError("model algorithm is not supported")
    if metadata["tenant_id"] != tenant_id or metadata["training_scope"] != "single_tenant":
        raise ValueError("model metadata does not match the requested tenant scope")
    if metadata["features"] != FEATURE_COLUMNS:
        raise ValueError("model feature list is incompatible with this release")
    rows = metadata["training_rows"]
    if isinstance(rows, bool) or not isinstance(rows, int) or rows < 2:
        raise ValueError("model training row count is invalid")
    for field in ("dataset_sha256", "artifact_sha256"):
        if not isinstance(metadata[field], str) or not _SHA256_RE.fullmatch(metadata[field]):
            raise ValueError(f"model metadata field {field} is not a valid SHA-256 digest")
    sequence = metadata["release_sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise ValueError("model release sequence must be a positive integer")
    if not isinstance(metadata["deployment_id"], str) or not metadata["deployment_id"].strip():
        raise ValueError("model deployment_id is invalid")
    if not isinstance(metadata["parameters"], dict) or not isinstance(metadata["warning"], str):
        raise ValueError("model metadata parameters or warning field is invalid")  # noqa: TRY004
    return metadata


def load_model(
    directory: str | Path,
    tenant_id: str,
    trusted_public_keys: dict[str, bytes | str],
    release_state_store: ReleaseStateStore,
    deployment_context,
    trusted_publisher_keyring,
) -> IsolationForest:
    """Load a locally controlled model only after metadata and artifact checks pass.

    Joblib uses Python serialization. Never load artifacts supplied by an untrusted party.
    The SHA-256 comparison detects artifact/metadata mismatch; it is not a digital signature
    and does not establish publisher authenticity. A trusted Ed25519 signature is mandatory.
    """
    if not tenant_id or not tenant_id.strip():
        raise ValueError("tenant_id is required to load a tenant-scoped model")
    from .trust_context import DeploymentTrustContext, TrustedPublisherKeyring
    if not isinstance(deployment_context, DeploymentTrustContext):
        raise TypeError("an authenticated deployment trust context is required")
    if not isinstance(trusted_publisher_keyring, TrustedPublisherKeyring):
        raise TypeError("a deployment-scoped trusted publisher keyring is required")
    if deployment_context.tenant_id != tenant_id:
        raise ValueError("deployment context tenant does not match requested tenant")
    if (trusted_publisher_keyring.tenant_id, trusted_publisher_keyring.deployment_id) != (
        deployment_context.tenant_id, deployment_context.deployment_id
    ):
        raise ValueError("publisher keyring is not scoped to the authenticated deployment")
    path = Path(directory)
    if release_state_store is None:
        raise ValueError("a durable customer release-state store is required")
    metadata = _read_and_validate_metadata(path / "model_metadata.json", tenant_id)
    if metadata["deployment_id"] != deployment_context.deployment_id:
        raise ValueError("model metadata does not match the authenticated deployment")
    if dict(trusted_public_keys) != dict(trusted_publisher_keyring.public_keys):
        raise ValueError("unscoped publisher keys cannot override the deployment keyring")
    verify_model_signature(path, metadata, trusted_publisher_keyring.public_keys)
    artifact_path = path / "isolation_forest.joblib"
    if artifact_path.is_symlink() or not artifact_path.is_file():
        raise ValueError("model artifact must be a regular, non-symlink file")
    actual_sha256 = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    if actual_sha256 != metadata["artifact_sha256"]:
        raise ValueError("model artifact SHA-256 verification failed")
    # Atomic customer-side compare-and-set; reject rollback before deserialization.
    release_state_store.accept_release(
        tenant_id=tenant_id,
        product=metadata["product"],
        release_sequence=metadata["release_sequence"],
        version=metadata["version"],
    )
    # Deserialization occurs only after signature, digest and anti-rollback checks.
    try:
        model = joblib.load(artifact_path)
    except Exception as exc:
        raise ValueError("model artifact could not be deserialized") from exc
    if not isinstance(model, IsolationForest):
        raise ValueError("model artifact does not contain a supported IsolationForest model")  # noqa: TRY004
    if getattr(model, "cephas_tenant_id_", None) != tenant_id:
        raise ValueError("loaded model tenant scope does not match the requested tenant")
    if getattr(model, "cephas_dataset_sha256_", None) != metadata["dataset_sha256"]:
        raise ValueError("loaded model training fingerprint does not match its metadata")
    if getattr(model, "n_features_in_", None) != len(FEATURE_COLUMNS):
        raise ValueError("loaded model feature count is incompatible")
    return model
