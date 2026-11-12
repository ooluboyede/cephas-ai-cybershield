# Customer-operated Release-Floor Anchor Service

This is a reference HTTPS service for the CyberShield anti-rollback anchor. It must be operated separately from the CyberShield application database and its backup/restore administration boundary.

## Security model

- HTTPS with TLS 1.2 minimum and mandatory client-certificate authentication (mTLS).
- Bearer tokens are stored as SHA-256 hashes in service configuration; each token is scoped to explicit tenant/deployment pairs and optionally product names.
- The service independently enforces scope; tenant/deployment identifiers supplied by the client are not trusted without the token scope check.
- PostgreSQL compare-and-set is atomic for each tenant/deployment/product.
- Accepted updates and idempotent installs are appended to an audit table in the same transaction as the floor update.
- Runtime DB role must have no UPDATE, DELETE or TRUNCATE privilege on the audit table. DDL ownership belongs to a separate administrator.
- The anchor database, credentials, backup policy, operators and recovery process must be independent of the CyberShield application database boundary.

This reference service is not certified or production-hardened. It does not itself provide HA, database backup immutability, key rotation orchestration, SIEM integration, external audit export or customer-specific disaster recovery. Those are deployment acceptance requirements. **Important threat boundary:** separating the anchor database from the application database protects against restoration of the application database only while the anchor remains trustworthy. The anchor database can itself be rolled back by an administrator or by restoring one of its own old backups; its local audit table would roll back with it. Protection against anchor-database rollback requires an additional independent witness, such as a customer-selected immutable/WORM audit service or hardware-backed monotonic checkpoint, with its own separately administered recovery boundary. That witness integration is not implemented in this reference service. Do not claim protection against compromise or rollback of the anchor's own administrators/database.

## 1. Provision the anchor database

Create a dedicated PostgreSQL database in a separately administered failure and backup domain. Run `schema.sql` as a database owner. Create a separate runtime role and grant only the privileges shown at the bottom of the schema. Do not use the database owner as the service account.

The anchor database must not be restored from the same snapshot set as the CyberShield operational database. Protect its backup and administrator paths independently.

## 2. Configure a scoped service identity

Generate a high-entropy bearer token in the customer's secrets manager. Never put the plaintext token in source control. Compute its SHA-256 digest and configure the digest (not the plaintext token) in `CEPHAS_ANCHOR_CLIENTS_JSON`.

Example configuration shape (replace all example values):

```json
{
  "<64-character-lowercase-sha256-token-digest>": {
    "client_id": "cybershield-prod-deployment-a",
    "scopes": [
      {
        "tenant_id": "tenant-a",
        "deployment_id": "deployment-a",
        "products": ["CEPHAS AI CyberShield"]
      }
    ]
  }
}
```

The service checks the token and exact tenant/deployment scope for every request. Product restrictions are optional; if omitted, the identity may access all products for that tenant/deployment.

## 3. Configure TLS and run

Install the package and `psycopg[binary]>=3.2,<4` in the isolated anchor-service environment. Provide:

- `CEPHAS_ANCHOR_DATABASE_URL`: runtime-role DSN for the dedicated anchor database.
- `CEPHAS_ANCHOR_CLIENTS_JSON`: JSON mapping SHA-256 token digests to client IDs and scopes.
- `CEPHAS_ANCHOR_TLS_CERT_FILE` and `CEPHAS_ANCHOR_TLS_KEY_FILE`: service certificate and private key.
- `CEPHAS_ANCHOR_CLIENT_CA_FILE`: CA used to validate CyberShield client certificates.
- Optional `CEPHAS_ANCHOR_BIND` (default `127.0.0.1`) and `CEPHAS_ANCHOR_PORT` (default `9443`).

Run:

```sh
python -m services.release_anchor.app
```

Use a dedicated host or isolated service network. Do not expose the WSGI listener to an untrusted network. Monitor service availability, database health, certificate expiry, authentication failures and audit insertion failures. Rotate bearer tokens and mTLS certificates through a separately authenticated administrative process.

## 4. Configure the CyberShield application

Construct the HTTPS client using the service CA bundle, client certificate/key and scoped bearer token. Compose it with the customer's operational PostgreSQL release-state store:

```python
from cybershield_ml.release_anchor import HttpReleaseFloorAnchor, AnchoredReleaseStateStore
from cybershield_ml.release_state import PostgresReleaseStateStore

anchor = HttpReleaseFloorAnchor(
    "https://release-anchor.customer.internal",
    bearer_token=customer_managed_anchor_token,
    ca_bundle="/etc/cephas/pki/anchor-ca.pem",
    client_cert="/etc/cephas/pki/cybershield-client.pem",
    client_key="/etc/cephas/pki/cybershield-client-key.pem",
)
database = PostgresReleaseStateStore(customer_application_db_connection_factory)
release_state = AnchoredReleaseStateStore(anchor=anchor, database_store=database)
```

Pass `release_state` to `load_model(..., release_state_store=release_state, ...)`. The client requires HTTPS, verifies the server certificate, supports optional mTLS, rejects redirects and has a bounded request timeout. Never disable certificate verification.

## 5. Recovery semantics

- Anchor floor higher than PostgreSQL: reconcile PostgreSQL forward to the anchor before accepting a model.
- PostgreSQL higher than anchor: fail closed; require an independently authorized recovery investigation. Never auto-promote the anchor from database-only state.
- Anchor unavailable, unauthenticated or malformed: fail closed.
- Anchor advances but PostgreSQL write fails: model load fails; a retry repairs PostgreSQL forward from the anchor.
- Both stores empty: first signed release may establish the floor in the anchor, then PostgreSQL.
- Database restore must not restore the independent anchor database. After recovery, verify floor equality and preserve the recovery audit record.

## 6. Customer acceptance still required

Before production use, validate the anchor database's independent backup/restore and failover behavior, database role privileges, mTLS identity issuance/revocation, token rotation, audit retention/export, monitoring, concurrency under load, service HA, network segmentation and incident recovery. The repository's unit tests are not a substitute for those customer-environment exercises.
