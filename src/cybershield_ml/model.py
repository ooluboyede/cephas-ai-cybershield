import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from . import FEATURE_SCHEMA_VERSION, __version__
from .features import FEATURE_COLUMNS


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
        n_estimators=200,
        contamination=contamination,
        random_state=seed,
        n_jobs=-1,
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


def save_model(model, features: pd.DataFrame, directory: str | Path):
    tenant_id = getattr(model, "cephas_tenant_id_", None)
    if not tenant_id:
        raise ValueError("refusing to save a model without verified tenant scope")
    if "tenant_id" not in features.columns or (
        not features.empty and not features["tenant_id"].eq(tenant_id).all()
    ):
        raise ValueError("model artifact data does not match the model tenant scope")
    validate_feature_frame(features)
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    artifact_path = path / "isolation_forest.joblib"
    joblib.dump(model, artifact_path)
    artifact_sha256 = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    metadata = {
        "product": "CEPHAS AI CyberShield",
        "version": __version__,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "algorithm": "IsolationForest",
        "tenant_id": tenant_id,
        "training_scope": "single_tenant",
        "features": FEATURE_COLUMNS,
        "training_rows": len(features),
        "dataset_sha256": fingerprint(features),
        "artifact_sha256": artifact_sha256,
        "parameters": model.get_params(),
        "warning": "Anomaly is not proof of malicious activity; analyst review required.",
    }
    metadata_path = path / "model_metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2, default=str), encoding="utf-8")
    return metadata
