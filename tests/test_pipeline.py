from datetime import datetime, timezone

import pandas as pd
import pytest

from cybershield_ml.evaluation import evaluate
from cybershield_ml.events import SecurityEvent
from cybershield_ml.features import FEATURE_COLUMNS, engineer_features
from cybershield_ml.model import save_model, score, train_model


def ev(i, kind, **kwargs):
    return SecurityEvent(event_id=str(i), tenant_id="t1", entity_id="u1",
        timestamp=datetime(2026, 1, 1, 10, 1, tzinfo=timezone.utc),
        event_type=kind, **kwargs)


def test_features_aggregate():
    rows = [ev(1, "auth_failure", source_ip="192.0.2.1"),
            ev(2, "auth_failure", source_ip="192.0.2.2"),
            ev(3, "network_connection", destination="api.invalid", outbound_bytes=900),
            ev(4, "privilege_change", privileged=True)]
    result = engineer_features(rows)
    assert len(result) == 1
    assert result.iloc[0].auth_failures_5m == 2
    assert result.iloc[0].unique_source_ips_5m == 2
    assert result.iloc[0].outbound_bytes_5m == 900
    assert result.iloc[0].privilege_events_5m == 1
    assert all(c in result for c in FEATURE_COLUMNS)


def test_empty_input_schema():
    assert engineer_features([]).empty


def test_naive_timestamp_rejected():
    with pytest.raises(ValueError):
        SecurityEvent(event_id="x", tenant_id="t", entity_id="u",
            timestamp=datetime(2026, 1, 1), event_type="auth_success")


def test_model_train_score_save(tmp_path):
    data = {c: [1., 2., 1., 3., 100., 2.] for c in FEATURE_COLUMNS}
    data["outbound_bytes_5m"] = [100., 120., 90., 110., 90_000_000., 130.]
    frame = pd.DataFrame(data)
    model = train_model(frame, contamination=.15)
    assert "anomaly_flag" in score(model, frame)
    save_model(model, frame, tmp_path)
    assert (tmp_path / "model_metadata.json").exists()
    assert (tmp_path / "isolation_forest.joblib").exists()


def test_invalid_training_rejected():
    with pytest.raises(ValueError):
        train_model(pd.DataFrame())


def test_evaluation():
    result = evaluate([0, 0, 1, 1], [0, 1, 1, 1])
    assert result["confusion_matrix_0_1"] == [[1, 1], [0, 2]]
