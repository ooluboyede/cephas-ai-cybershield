from pathlib import Path

from cybershield_ml.features import engineer_features
from cybershield_ml.model import save_model, score, train_model
from cybershield_ml.synthetic import synthetic_events


def main():
    events = synthetic_events()
    features = engineer_features(events)
    tenant_id = "synthetic-tenant"
    model = train_model(features, tenant_id=tenant_id, contamination=0.03)
    tenant_features = features.loc[features["tenant_id"] == tenant_id].copy()
    results = score(model, tenant_features)
    output = Path("artifacts/demo")
    save_model(model, tenant_features, output)
    results.to_csv(output / "scored_features.csv", index=False)
    print(
        f"{len(events)} synthetic events; {len(tenant_features)} tenant feature rows; "
        f"{int(results.anomaly_flag.sum())} anomaly candidates flagged for review."
    )


if __name__ == "__main__":
    main()
