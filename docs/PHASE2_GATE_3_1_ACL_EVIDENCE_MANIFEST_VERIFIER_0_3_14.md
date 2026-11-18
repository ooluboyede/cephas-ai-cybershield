# Phase 2 Gate 3.1 — signed ACL evidence manifest verifier (0.3.14)

## Purpose

Provide an offline, fail-closed verifier for the customer evidence package defined in Gate 3.0. It verifies an Ed25519 signature over the exact manifest bytes, checks that all 14 required evidence IDs are present exactly once, rejects unsafe paths and symlinks, and recomputes SHA-256 for every referenced artifact.

## Usage

Run in the customer-controlled evidence environment:

```bash
python scripts/acl_evidence_manifest.py \
  --manifest /secure/evidence/manifest.json \
  --evidence-root /secure/evidence/files \
  --signature /secure/evidence/manifest.sig \
  --public-key /secure/evidence/manifest-signer-public.pem
```

The detached signature must be produced by the customer's approved evidence-signing process. The public key must be pinned out-of-band and supplied through an approved trust channel. Do not place private signing keys in this repository or pass them to this verifier.

The manifest is signed as exact raw bytes; reformatting or editing it after signing invalidates the signature. Each artifact entry has `id`, relative `path`, and lowercase SHA-256 `sha256`. Required IDs are ACL-001 through ACL-014. Evidence files must be regular files under the supplied evidence root; absolute paths, traversal, symlinks, missing files, duplicate IDs/paths, unknown IDs and hash mismatches fail closed.

## Evidence boundary

This verifies package integrity and signer authenticity only relative to the customer-pinned Ed25519 public key. It does not establish that an artifact is truthful, that Azure produced a receipt, that a certificate was authorized by Azure, or that the signer is authorized unless the customer independently governs and pins that key. It does not contact Azure or replace Gigabrute's review.

Tests use synthetic local evidence and ephemeral signing keys. They are Class A software tests only, not live Azure evidence. No secrets, bearer tokens, or private keys are needed by the verifier.

## Exit criteria

- [ ] Exact-head CI passes lint, unit and PostgreSQL integration suites.
- [ ] Customer validates the verifier with its own approved signer key and a complete controlled evidence package.
- [ ] Gigabrute confirms the manifest trust model and evidence package acceptance.
- [ ] Genuine Class B/C provider and operational evidence remains mandatory; this verifier does not create it.

No GIGA-SEC-02 closure or production certification is claimed. PRs #8 and #9 remain untouched. This PR is draft and unmerged pending review.
