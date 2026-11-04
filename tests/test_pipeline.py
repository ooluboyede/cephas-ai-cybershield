from datetime import datetime, timezone
import hashlib
import json

import pandas as pd
import pytest

from cybershield_ml.evaluation import evaluate
from cybershield_ml.events import SecurityEvent
from cybershield_ml.features import FEATURE_COLUMNS, deduplicate_events, engineer_features
from cybershield_ml.model import fingerprint, save_model, score, train_model


def ev(i, kind, tenant="t1", **kwargs):
    return SecurityEvent(
        event_id=str(i),
        tenant_id=tenant,
        entity_id="u1",
        timestamp=datetime(2026, 1, 1, 10, 1, tzinfo=timezone.utc),
        event_type=kind,
        **kwargs,
    )


def sample_features():
    data = {column: [1.0, 2.0, 1.0, 3.0, 100.0, 2.0] for column in FEATURE_COLUMNS}
    data["outbound_bytes_5m"] = [100.0, 120.0, 90.0, 110.0, 90_000_000.0, 130.0]
    data["tenant_id"] = ["t1"] * 6
    data["entity_id"] = [f"u{i}" for i in range(6)]
    data["window_start"] = pd.date_range("2026-01-01", periods=6, freq="5min", tz="UTC")
    return pd.DataFrame(data)


def test_features_aggregate():
    rows = [
        ev(1, "auth_failure", source_ip="192.0.2.1"),
        ev(2, "auth_failure", source_ip="192.0.2.2"),
        ev(3, "network_connection", destination="api.invalid", outbound_bytes=900),
        ev(4, "privilege_change", privileged=True),
    ]
    result = engineer_features(rows)
    assert len(result) == 1
    assert result.iloc[0].auth_failures_5m == 2
    assert result.iloc[0].unique_source_ips_5m == 2
    assert result.iloc[0].outbound_bytes_5m == 900
    assert result.iloc[0].privilege_events_5m == 1
    assert all(column in result for column in FEATURE_COLUMNS)


def test_empty_input_schema():
    result = engineer_features([])
    assert result.empty
    assert "tenant_id" in result.columns


def test_naive_timestamp_rejected():
    with pytest.raises(ValueError):
        SecurityEvent(
            event_id="x",
            tenant_id="t",
            entity_id="u",
            timestamp=datetime(2026, 1, 1),
            event_type="auth_success",
        )


def test_exact_duplicate_events_are_counted_once():
    event = ev(1, "auth_failure", source_ip="192.0.2.1")
    features = engineer_features([event, event])
    assert features.iloc[0].event_rate_5m == 1
    assert features.iloc[0].auth_failures_5m == 1
    assert len(deduplicate_events([event, event])) == 1


def test_conflicting_duplicate_event_id_is_rejected():
    first = ev(1, "auth_failure")
    replay_with_changed_payload = ev(1, "auth_success")
    with pytest.raises(ValueError, match="conflicting payloads"):
        engineer_features([first, replay_with_changed_payload])


def test_event_ids_are_scoped_by_tenant():
    rows = [ev(1, "auth_failure", tenant="t1"), ev(1, "auth_success", tenant="t2")]
    result = engineer_features(rows)
    assert set(result.tenant_id) == {"t1", "t2"}
    assert result.event_rate_5m.sum() == 2


def test_model_training_is_scoped_to_one_tenant(tmp_path):
    frame = sample_features()
    other_tenant = frame.copy()
    other_tenant["tenant_id"] = "t2"
    combined = pd.concat([frame, other_tenant], ignore_index=True)
    model = train_model(combined, tenant_id="t1", contamination=0.15)
    assert model.cephas_tenant_id_ == "t1"
    assert model.cephas_dataset_sha256_ == fingerprint(frame)
    result = score(model, frame)
    assert set(result.tenant_id) == {"t1"}
    metadata = save_model(model, frame, tmp_path)
    assert metadata["tenant_id"] == "t1"
    assert metadata["training_scope"] == "single_tenant"
    assert metadata["artifact_sha256"] == hashlib.sha256(
        (tmp_path / "isolation_forest.joblib").read_bytes()
    ).hexdigest()
    stored = json.loads((tmp_path / "model_metadata.json").read_text())
    assert stored["artifact_sha256"] == metadata["artifact_sha256"]


def test_training_requires_explicit_tenant_scope():
    with pytest.raises(TypeError):
        train_model(sample_features())


def test_training_rejects_unknown_tenant():
    with pytest.raises(ValueError, match="no training rows"):
        train_model(sample_features(), tenant_id="missing")


def test_scoring_rejects_cross_tenant_rows():
    frame = sample_features()
    model = train_model(frame, tenant_id="t1", contamination=0.15)
    other = frame.copy()
    other["tenant_id"] = "t2"
    with pytest.raises(ValueError, match="outside the model tenant scope"):
        score(model, other)


@pytest.mark.parametrize(
    "bad_value",
    [float("nan"), float("inf"), -1.0, "not-a-number"],
)
def test_invalid_feature_values_rejected(bad_value):
    frame = sample_features()
    frame.loc[0, "auth_failures_5m"] = bad_value
    with pytest.raises(ValueError):
        train_model(frame, tenant_id="t1")


def test_model_rejects_missing_feature_column():
    frame = sample_features().drop(columns=["event_rate_5m"])
    with pytest.raises(ValueError, match="missing features"):
        train_model(frame, tenant_id="t1")


def test_model_train_score_save(tmp_path):
    frame = sample_features()
    model = train_model(frame, tenant_id="t1", contamination=0.15)
    result = score(model, frame)
    assert "anomaly_flag" in result
    assert len(result) == len(frame)
    save_model(model, frame, tmp_path)
    assert (tmp_path / "model_metadata.json").exists()
    assert (tmp_path / "isolation_forest.joblib").exists()


def test_fingerprint_is_stable():
    frame = sample_features()
    assert fingerprint(frame) == fingerprint(frame.copy())


def test_evaluation():
    result = evaluate([0, 0, 1, 1], [0, 1, 1, 1])
    assert result["confusion_matrix_0_1"] == [[1, 1], [0, 2]]
