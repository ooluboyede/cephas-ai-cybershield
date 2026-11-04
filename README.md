# CEPHAS AI CyberShield

Customer-hosted AI cybersecurity platform. This repository contains the ML foundation for feature engineering and baseline anomaly detection.

## Current foundation
- Validated, timezone-aware security-event contract
- Versioned five-minute behavioural feature pipeline
- Scikit-learn Isolation Forest baseline
- Model metadata and SHA-256 training-data fingerprint
- Synthetic event generator, evaluation utilities and tests
- GitHub Actions CI workflow

## Run locally
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
pytest
python scripts/train_demo.py
```

## Security and readiness
This is an engineering foundation, not a production-ready security product or validated threat model. It uses synthetic data. An anomaly is not proof of compromise. Validate with representative, authorised and independently labelled datasets; calibrate thresholds with analysts; monitor drift and false positives; require human approval for disruptive actions. Never upload customer telemetry, credentials, private keys or customer model artifacts to GitHub.

Not yet included: live endpoint agents, SIEM/EDR/firewall connectors, streaming ingestion, production identity/MFA, database-enforced tenant isolation, signed model packages, drift alerting, high availability, automated containment, penetration testing or certification.