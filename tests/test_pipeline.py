import hashlib
import json
from datetime import datetime, timezone

import pandas as pd
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cybershield_ml.evaluation import evaluate
from cybershield_ml.events import SecurityEvent
from cybershield_ml.features import FEATURE_COLUMNS, deduplicate_events, engineer_features
from cybershield_ml.model import fingerprint, save_model, score, train_model
from cybershield_ml.model import load_model as _load_model
from cybershield_ml.signing import sign_model
from cybershield_ml.trust_context import DeploymentTrustContext, TrustedPublisherKeyring


class MemoryReleaseStateStore:
    """Test-only stand-in; production deployments must provide durable shared storage."""

    def __init__(self):
        self.state = {}

    def accept_release(self, *, tenant_id, product, release_sequence, version):
        key = (tenant_id, product)
        current = self.state.get(key)
        if current is not None:
            current_sequence, current_version = current
            if release_sequence < current_sequence:
                raise ValueError("model release is older than the accepted release floor")
            if release_sequence == current_sequence and version != current_version:
                raise ValueError("release sequence is already bound to another version")
        self.state[key] = (release_sequence, version)


def load_model(*args, **kwargs):
    """Use isolated test trust objects and state unless a test supplies explicit ones."""
    kwargs.setdefault("release_state_store", MemoryReleaseStateStore())
    tenant_id = kwargs.get("tenant_id", args[1] if len(args) > 1 else None)
    public_keys = kwargs.get("trusted_public_keys", args[2] if len(args) > 2 else None)
    kwargs.setdefault(
        "deployment_context",
        DeploymentTrustContext(tenant_id=tenant_id, deployment_id="default"),
    )
    kwargs.setdefault(
        "trusted_publisher_keyring",
        TrustedPublisherKeyring(
            tenant_id=tenant_id, deployment_id="default", public_keys=public_keys or {}
        ),
    )
    return _load_model(*args, **kwargs)


@pytest.fixture
def publisher_keyring():
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, {"cephas-test-2026": public_pem}


def sign_test_model(directory, publisher_keyring):
    private_pem, public_keys = publisher_keyring
    sign_model(directory, "t1", private_pem, "cephas-test-2026")
    return public_keys


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


def test_save_model_rejects_dataset_different_from_training_data(tmp_path):
    frame = sample_features()
    model = train_model(frame, tenant_id="t1", contamination=0.15)
    altered = frame.copy()
    altered.loc[0, "auth_failures_5m"] = 99.0
    with pytest.raises(ValueError, match="does not match the model training dataset"):
        save_model(model, altered, tmp_path)
    assert not (tmp_path / "isolation_forest.joblib").exists()


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


def test_model_load_round_trip_and_tenant_scope(tmp_path, publisher_keyring):
    frame = sample_features()
    trained = train_model(frame, tenant_id="t1", contamination=0.15)
    save_model(trained, frame, tmp_path)
    trusted = sign_test_model(tmp_path, publisher_keyring)
    loaded = load_model(tmp_path, tenant_id="t1", trusted_public_keys=trusted)
    assert loaded.cephas_tenant_id_ == "t1"
    assert loaded.cephas_dataset_sha256_ == trained.cephas_dataset_sha256_
    assert len(score(loaded, frame)) == len(frame)
    with pytest.raises(ValueError, match="requested tenant scope"):
        load_model(tmp_path, tenant_id="t2", trusted_public_keys=trusted)


def test_loader_rejects_artifact_tampering_before_deserialization(tmp_path, monkeypatch, publisher_keyring):
    import cybershield_ml.model as model_module

    frame = sample_features()
    save_model(train_model(frame, tenant_id="t1", contamination=0.15), frame, tmp_path)
    trusted = sign_test_model(tmp_path, publisher_keyring)
    artifact = tmp_path / "isolation_forest.joblib"
    artifact.write_bytes(artifact.read_bytes() + b"tampered")

    def unexpected_load(_path):
        pytest.fail("joblib.load must not run before artifact hash verification")

    monkeypatch.setattr(model_module.joblib, "load", unexpected_load)
    with pytest.raises(ValueError, match="SHA-256 verification failed"):
        load_model(tmp_path, tenant_id="t1", trusted_public_keys=trusted)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("version", "99.0.0", "model version is incompatible"),
        ("metadata_schema_version", "99.0.0", "metadata schema version is incompatible"),
        ("feature_schema_version", "99.0.0", "feature schema version is incompatible"),
        ("algorithm", "UnknownModel", "algorithm is not supported"),
        ("features", ["unexpected_feature"], "feature list is incompatible"),
        ("tenant_id", "t2", "requested tenant scope"),
        ("artifact_sha256", "not-a-digest", "not a valid SHA-256 digest"),
    ],
)
def test_loader_rejects_incompatible_metadata(tmp_path, field, value, message, publisher_keyring):
    frame = sample_features()
    save_model(train_model(frame, tenant_id="t1", contamination=0.15), frame, tmp_path)
    trusted = sign_test_model(tmp_path, publisher_keyring)
    metadata_path = tmp_path / "model_metadata.json"
    metadata = json.loads(metadata_path.read_text())
    metadata[field] = value
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_model(tmp_path, tenant_id="t1", trusted_public_keys=trusted)


def test_loader_rejects_malformed_metadata(tmp_path):
    (tmp_path / "model_metadata.json").write_text("{broken", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON"):
        load_model(tmp_path, tenant_id="t1", trusted_public_keys={})


def test_loader_rejects_metadata_missing_required_fields(tmp_path):
    (tmp_path / "model_metadata.json").write_text(json.dumps({"product": "CEPHAS"}))
    with pytest.raises(ValueError, match="missing fields"):
        load_model(tmp_path, tenant_id="t1", trusted_public_keys={})


def test_loader_rejects_model_payload_with_wrong_tenant(tmp_path, publisher_keyring):
    import joblib

    frame = sample_features()
    model = train_model(frame, tenant_id="t1", contamination=0.15)
    save_model(model, frame, tmp_path)
    model.cephas_tenant_id_ = "t2"
    artifact = tmp_path / "isolation_forest.joblib"
    joblib.dump(model, artifact)
    metadata_path = tmp_path / "model_metadata.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["artifact_sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    private_pem, trusted = publisher_keyring
    sign_model(tmp_path, "t1", private_pem, "cephas-test-2026")
    with pytest.raises(ValueError, match="loaded model tenant scope"):
        load_model(tmp_path, tenant_id="t1", trusted_public_keys=trusted)


def test_loader_rejects_symlinked_artifact(tmp_path, publisher_keyring):
    frame = sample_features()
    model = train_model(frame, tenant_id="t1", contamination=0.15)
    save_model(model, frame, tmp_path)
    trusted = sign_test_model(tmp_path, publisher_keyring)
    artifact = tmp_path / "isolation_forest.joblib"
    target = tmp_path / "real-model.joblib"
    artifact.rename(target)
    artifact.symlink_to(target)
    with pytest.raises(ValueError, match="regular, non-symlink"):
        load_model(tmp_path, tenant_id="t1", trusted_public_keys=trusted)


def test_loader_rejects_unknown_publisher_key(tmp_path, publisher_keyring):
    frame = sample_features()
    save_model(train_model(frame, tenant_id="t1", contamination=0.15), frame, tmp_path)
    sign_test_model(tmp_path, publisher_keyring)
    with pytest.raises(ValueError, match="not trusted"):
        load_model(tmp_path, "t1", {"untrusted": publisher_keyring[1]["cephas-test-2026"]})


def test_loader_rejects_modified_metadata_signature(tmp_path, publisher_keyring):
    frame = sample_features()
    save_model(train_model(frame, tenant_id="t1", contamination=0.15), frame, tmp_path)
    trusted = sign_test_model(tmp_path, publisher_keyring)
    metadata_path = tmp_path / "model_metadata.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["warning"] = "changed after signing"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(ValueError, match="signature verification failed"):
        load_model(tmp_path, "t1", trusted)


def test_loader_rejects_modified_signature(tmp_path, publisher_keyring):
    frame = sample_features()
    save_model(train_model(frame, tenant_id="t1", contamination=0.15), frame, tmp_path)
    trusted = sign_test_model(tmp_path, publisher_keyring)
    signature_path = tmp_path / "model_signature.json"
    document = json.loads(signature_path.read_text())
    document["signature"] = "AA=="
    signature_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="signature verification failed"):
        load_model(tmp_path, "t1", trusted)


def test_loader_requires_signature_and_keyring(tmp_path):
    frame = sample_features()
    save_model(train_model(frame, tenant_id="t1", contamination=0.15), frame, tmp_path)
    with pytest.raises(ValueError, match="signature file is required"):
        load_model(tmp_path, "t1", {"known": b"unused"})


def test_signature_binds_exact_metadata_bytes(tmp_path, publisher_keyring):
    frame = sample_features()
    save_model(train_model(frame, tenant_id="t1", contamination=0.15), frame, tmp_path)
    trusted = sign_test_model(tmp_path, publisher_keyring)
    metadata_path = tmp_path / "model_metadata.json"
    original = metadata_path.read_bytes()

    # Reordering JSON keys preserves the parsed object but changes the signed bytes.
    parsed = json.loads(original)
    metadata_path.write_text(json.dumps(dict(reversed(list(parsed.items())))), encoding="utf-8")

    with pytest.raises(ValueError, match="signature verification failed"):
        load_model(tmp_path, "t1", trusted)


def test_signature_binds_metadata_whitespace_bytes(tmp_path, publisher_keyring):
    frame = sample_features()
    save_model(train_model(frame, tenant_id="t1", contamination=0.15), frame, tmp_path)
    trusted = sign_test_model(tmp_path, publisher_keyring)
    metadata_path = tmp_path / "model_metadata.json"
    metadata_path.write_bytes(metadata_path.read_bytes() + b"\n")

    with pytest.raises(ValueError, match="signature verification failed"):
        load_model(tmp_path, "t1", trusted)


def test_signature_verification_uses_exact_key_id_without_fallback(tmp_path, publisher_keyring):
    frame = sample_features()
    save_model(train_model(frame, tenant_id="t1", contamination=0.15), frame, tmp_path)
    trusted = sign_test_model(tmp_path, publisher_keyring)
    signature_path = tmp_path / "model_signature.json"
    document = json.loads(signature_path.read_text(encoding="utf-8"))
    document["key_id"] = "cephas-test-2026:unknown"
    signature_path.write_text(json.dumps(document), encoding="utf-8")

    # Even when the same public key is configured under another ID, no fallback is allowed.
    with pytest.raises(ValueError, match="not trusted"):
        load_model(tmp_path, "t1", {"cephas-test-2026": trusted["cephas-test-2026"]})


@pytest.mark.parametrize("key_id", ["", " leading", "trailing ", "bad\\nvalue", "x" * 129])
def test_signing_rejects_malformed_key_ids(tmp_path, publisher_keyring, key_id):
    frame = sample_features()
    save_model(train_model(frame, tenant_id="t1", contamination=0.15), frame, tmp_path)
    private_pem, _ = publisher_keyring
    with pytest.raises(ValueError, match="key_id"):
        sign_model(tmp_path, "t1", private_pem, key_id)


def test_loader_rejects_model_from_another_deployment(tmp_path, publisher_keyring):
    frame = sample_features()
    save_model(train_model(frame, tenant_id="t1", contamination=0.15), frame, tmp_path,
               deployment_id="deployment-a")
    trusted = sign_test_model(tmp_path, publisher_keyring)
    with pytest.raises(ValueError, match="authenticated deployment"):
        load_model(tmp_path, tenant_id="t1", trusted_public_keys=trusted)


def test_loader_rejects_cross_tenant_publisher_keyring(tmp_path, publisher_keyring):
    frame = sample_features()
    save_model(train_model(frame, tenant_id="t1", contamination=0.15), frame, tmp_path)
    trusted = sign_test_model(tmp_path, publisher_keyring)
    with pytest.raises(ValueError, match="not scoped to the authenticated deployment"):
        load_model(
            tmp_path, tenant_id="t1", trusted_public_keys=trusted,
            trusted_publisher_keyring=TrustedPublisherKeyring(
                tenant_id="t2", deployment_id="default", public_keys=trusted
            ),
        )


def test_loader_rejects_cross_deployment_publisher_keyring(tmp_path, publisher_keyring):
    frame = sample_features()
    save_model(train_model(frame, tenant_id="t1", contamination=0.15), frame, tmp_path)
    trusted = sign_test_model(tmp_path, publisher_keyring)
    with pytest.raises(ValueError, match="not scoped to the authenticated deployment"):
        load_model(
            tmp_path, tenant_id="t1", trusted_public_keys=trusted,
            trusted_publisher_keyring=TrustedPublisherKeyring(
                tenant_id="t1", deployment_id="deployment-other", public_keys=trusted
            ),
        )
