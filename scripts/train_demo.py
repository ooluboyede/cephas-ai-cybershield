from pathlib import Path

from cybershield_ml.features import engineer_features
from cybershield_ml.model import save_model, score, train_model
from cybershield_ml.synthetic import synthetic_events

def main():
    events = synthetic_events()
    features = engineer_features(events)
    model = train_model(features, contamination=0.03)
    results = score(model, features)
    output = Path("artifacts/demo")
    save_model(model, features, output)
    results.to_csv(output / "scored_features.csv", index=False)
    print(f"{len(events)} synthetic events; {len(features)} feature rows; "
          f"{int(results.anomaly_flag.sum())} anomaly candidates flagged for review.")

if __name__ == "__main__":
    main()
