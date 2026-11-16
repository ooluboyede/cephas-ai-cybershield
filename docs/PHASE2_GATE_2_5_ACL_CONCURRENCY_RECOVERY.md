# Phase 2 Gate 2.5 — ACL concurrency and uncertain-write recovery

**Status:** Test implementation candidate; execution and live provider validation OPEN  
**Branch:** `milestone/cybershield-0.3.8-acl-concurrency-recovery-gate-2-5`  
**Parent:** Gate 2.4 / PR #20  
**Scope:** Concurrent writers, atomic compare-and-append outcomes, timeout-after-commit recovery, and retry after receipt retrieval interruption

## 1. Implemented

Adds `tests/test_acl_concurrency_recovery.py`, a deterministic thread-safe fake ACL ledger and four adapter-level scenarios:

1. **Eight concurrent exact retries:** all callers converge on one committed transaction ID; only one ledger entry exists.
2. **Eight competing checkpoints with the same predecessor:** exactly one writer succeeds; the other seven receive a compare-and-append conflict; no fork is accepted by the fake ledger.
3. **Timeout after durable commit:** the fake ledger commits the transaction and drops the POST response; the adapter discovers the exact checkpoint by collection scan, retrieves the original transaction receipt, and returns the original transaction ID.
4. **Receipt response lost after commit:** the first caller receives an unavailable error after the commit; an exact retry locates and verifies the original transaction rather than creating a second ledger entry.

The tests exercise the existing Gate 2.3 adapter recovery behavior; this gate does not replace the provider's atomic compare-and-append UDF with client-side locking.

## 2. Required concurrency invariant

For a given predecessor checkpoint, no two distinct successor checkpoints may both be accepted. The ledger-side UDF must perform the predecessor comparison and append atomically inside the transaction. A client-side mutex is insufficient because writers may run on separate hosts or processes.

An exact replay with the same operation ID and exact checkpoint may recover the original committed transaction. A reused operation ID with different checkpoint content, a competing successor, ambiguous collection results, or an unresolved transaction must fail closed.

## 3. Test harness boundary

The fake ledger serializes its state transitions under a process-local lock and simulates the adapter's documented HTTP operations. It is useful for deterministic adapter regression tests, but it is not a substitute for Azure Confidential Ledger / CCF concurrency behavior, distributed-node failover, or a live deployed UDF.

The fake's compare-and-append behavior is a test model of the required invariant, not independent proof that the deployed CCF UDF implements it correctly.

## 4. Not yet implemented or proven

- No live 10+ writer stress test against a customer Azure Confidential Ledger.
- No process-kill or host-restart test between POST acceptance, commit, receipt retrieval, and local acknowledgement.
- No Azure ledger node failover, region failover, backup/restore, or disaster-recovery exercise.
- No independent durable client-side transaction journal. The current recovery source is the customer ledger's committed collection and transaction status/receipt APIs.
- No live proof of transaction-ID stability and receipt availability across failover.
- No test that demonstrates recovery when collection pagination is incomplete or the provider's read API is temporarily unavailable, beyond existing fail-closed unit coverage.
- No production certification or closure of GIGA-SEC-02.

## 5. Validation status

- Tests are authored but **not executed** in this session.
- GitHub Actions/workflows remain paused at the user's request until Monday.
- No live customer ACL endpoint, credentials, or ledger was supplied.
- Exact-head local test execution and CI remain required before review.
- Live validation should use at least 10 independent writer processes/hosts, inject dropped responses after commit, restart adapter hosts, and verify a single linear checkpoint history with no duplicate or forked operation IDs.

## 6. Exit criteria

Gate 2.5 can be considered technically validated only after:
- exact-head local tests pass;
- exact-head CI passes after workflow execution resumes;
- live ACL tests prove one-winner compare-and-append under competing writers;
- dropped POST and receipt responses recover the original transaction and receipt;
- process restart does not create a second commit;
- an independent reviewer inspects the CCF UDF atomicity and retry semantics.

**Release status:** Draft implementation candidate; no production-readiness claim.
