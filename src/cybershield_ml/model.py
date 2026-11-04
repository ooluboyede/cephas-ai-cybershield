import hashlib
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from . import FEATURE_SCHEMA_VERSION, __version__
from .features import FEATURE_COLUMNS

def fingerprint(features: pd.DataFrame) -> str:
    return hashlib.sha256(features[FEATURE_COLUMNS].to_csv(index=False).encode()).hexdigest()

def train_model(features: pd.DataFrame, contamination: float = 0.02, seed: int = 42):
    if features.empty:
        raise ValueError("training features cannot be empty")
    missing = set(FEATURE_COLUMNS) - set(features.columns)
    if missing:
        raise ValueError(f"missing features: {sorted(missing)}")
    if not 0 < contamination <= 0.5:
        raise ValueError("contamination must be in (0, 0.5]")
    model = IsolationForest(n_estimators=200, contamination=contamination,
                            random_state=seed, n_jobs=-1)
    model.fit(features[FEATURE_COLUMNS])
    return model

def score(model, features: pd.DataFrame) -> pd.DataFrame:
    result = features.copy()
    if result.empty:
        result["anomaly_score"] = pd.Series(dtype=float)
        result["anomaly_flag"] = pd.Series(dtype=int)
        return result
    result["anomaly_score"] = model.decision_function(features[FEATURE_COLUMNS])
    result["anomaly_flag"] = (model.predict(features[FEATURE_COLUMNS]) == -1).astype(int)
    return result

def save_model(model, features: pd.DataFrame, directory: str | Path):
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path / "isolation_forest.joblib")
    metadata = {"product": "CEPHAS AI CyberShield", "version": __version__,
        "feature_schema_version": FEATURE_SCHEMA_VERSION, "algorithm": "IsolationForest",
        "features": FEATURE_COLUMNS, "training_rows": len(features),
        "dataset_sha256": fingerprint(features), "parameters": model.get_params(),
        "warning": "Anomaly is not proof of malicious activity; analyst review required."}
    (path / "model_metadata.json").write_text(json.dumps(metadata, indent=2, default=str))
