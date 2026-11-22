# Gate 3.2A — Witness-first authority and ACL receipt corrections

Base: `5b9e60deb18f486dc5354e1dbdf126971920a1a6`

## Implemented scope

- GIGA-P2-001: add `WitnessedReleaseStateStore`; model loading requires this store and supplies signed-release identity fields. The witness is read and its receipt verified before release acceptance. A new checkpoint is compare-and-appended to the witness before either mirror advances. Lagging HTTPS/PostgreSQL mirrors heal forward; either mirror ahead of the witness fails closed.
- GIGA-P2-002: construct structured CEPHAS checkpoint metadata and a CCF `ClaimDigest` wrapper. POST `applicationClaims` and native SDK verification use the typed wrapper; the receipt envelope retains structured CEPHAS claim metadata.
- GIGA-P2-003: offline receipt verification binds the envelope transaction ID to `leafComponents.commitEvidence` using `ce:<transactionId>:<hex>`.

## Evidence boundary and remaining integration

The witness-first store consumes the provider-neutral witness contract (`read_checkpoint`, `compare_and_append`, `verify_receipt`). The current Azure adapter still needs a concrete implementation of that read/append/verify contract; this branch's Class A tests exercise the coordinator with a controlled fake witness. This is not live Azure evidence and does not close provider integration by itself.

The ACL claim representation must be confirmed with the pinned Microsoft SDK and a genuine receipt in customer-controlled non-production ACL before provider acceptance. No credentials or private keys are included.

PRs #8 and #9 remain untouched. No PRs are merged. GIGA-SEC-02 and production certification remain open.
