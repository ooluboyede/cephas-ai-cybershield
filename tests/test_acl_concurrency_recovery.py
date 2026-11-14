"""Concurrency and uncertain-write recovery tests for the ACL adapter.

These tests exercise adapter behavior against a deterministic, thread-safe fake
ledger. They do not substitute for concurrency testing against a live CCF ledger.
"""
from __future__ import annotations

import concurrent.futures
import dataclasses
import hashlib
import json
import threading

import pytest

from cybershield_ml.azure_confidential_ledger import (
    ACLConflict,
    ACLUnavailable,
    AzureConfidentialLedgerAdapter,
)
from cybershield_ml.release_witness import WitnessCheckpoint


UDF_CODE = "export function main() { return true; }"


def make_checkpoint(operation_id: str = "gate25-operation-1", artifact: str = "b" * 64):
    return WitnessCheckpoint(
        tenant_id="tenant-a",
        deployment_id="deployment-a",
        product="CyberShield",
        release_sequence=1,
        release_version="0.3.8",
        metadata_sha256="a" * 64,
        artifact_sha256=artifact,
        publisher_key_id="publisher-2026",
        publisher_signature_sha256="c" * 64,
        previous_checkpoint_sha256=None,
        operation_id=operation_id,
    )


class ConcurrentFakeLedger:
    """Atomic fake of the minimal ACL operations used by the adapter."""

    def __init__(self, *, lose_first_post_response: bool = False):
        self.lock = threading.RLock()
        self.entries = []
        self.transactions = {}
        self.next_id = 1
        self.lose_first_post_response = lose_first_post_response
        self.lost_response = False
        self.calls = []

    def request_json(self, method, path, body=None):
        with self.lock:
            self.calls.append((method, path, body))
            if method == "GET" and path.startswith("/app/userDefinedFunctions/"):
                return {"code": UDF_CODE}

            if method == "POST" and path.startswith("/app/transactions?"):
                payload = json.loads(body["contents"])
                checkpoint = payload["checkpoint"]
                operation_id = payload["operation_id"]

                for existing in self.entries:
                    if existing["operation_id"] == operation_id:
                        raise ACLConflict("operation already committed")
                if self.entries:
                    latest = self.entries[-1]
                    if checkpoint["previous_checkpoint_sha256"] != latest["checkpoint_sha256"]:
                        raise ACLConflict("predecessor changed; compare-and-append conflict")
                elif checkpoint["previous_checkpoint_sha256"] is not None:
                    raise ACLConflict("unexpected non-empty predecessor")

                transaction_id = f"2.{self.next_id}"
                self.next_id += 1
                entry = {
                    "contents": body["contents"],
                    "transactionId": transaction_id,
                    "collectionId": "cephas-release-witness-v2",
                    "operation_id": operation_id,
                    "checkpoint_sha256": payload["checkpoint_sha256"],
                }
                self.entries.append(entry)
                self.transactions[transaction_id] = {
                    "state": "Committed",
                    "receipt": {
                        "leafComponents": {
                            "claimsDigest": "e" * 64,
                            "writeSetDigest": "f" * 64,
                        }
                    },
                }
                if self.lose_first_post_response and not self.lost_response:
                    self.lost_response = True
                    raise ACLUnavailable("simulated response loss after durable commit")
                return {"transactionId": transaction_id}

            if method == "GET" and path.startswith("/app/transactions?"):
                return {"state": "Ready", "entries": list(self.entries)}

            parts = path.split("/")
            if method == "GET" and len(parts) >= 5 and parts[3] in self.transactions:
                transaction_id = parts[3]
                if parts[4] == "status":
                    return {"state": self.transactions[transaction_id]["state"]}
                if parts[4] == "receipt":
                    return {
                        "state": "Ready",
                        "transactionId": transaction_id,
                        "receipt": self.transactions[transaction_id]["receipt"],
                    }
            raise AssertionError(f"unexpected fake-ledger request: {method} {path}")


def make_adapter(ledger):
    return AzureConfidentialLedgerAdapter(
        transport=ledger,
        service_identity_certificate_pem="test-pinned-service-identity",
        expected_udf_sha256=hashlib.sha256(UDF_CODE.encode()).hexdigest(),
        poll_interval_seconds=0,
        native_receipt_verifier=lambda *_args, **_kwargs: None,
        commit_poll_attempts=2,
        receipt_poll_attempts=2,
    )


def append(adapter, cp):
    return adapter.append(
        cp,
        expected_previous_checkpoint_sha256=cp.previous_checkpoint_sha256,
    )


def test_concurrent_exact_retries_converge_on_one_transaction():
    ledger = ConcurrentFakeLedger()
    instance = make_adapter(ledger)
    cp = make_checkpoint()

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _index: append(instance, cp), range(8)))

    assert {result.transaction_id for result in results} == {"2.1"}
    assert len(ledger.entries) == 1


def test_concurrent_competing_checkpoints_have_exactly_one_winner():
    ledger = ConcurrentFakeLedger()
    instance = make_adapter(ledger)
    candidates = [
        make_checkpoint(operation_id=f"gate25-competing-{index}", artifact=f"{index:x}" * 64)
        for index in range(8)
    ]

    def attempt(cp):
        try:
            return append(instance, cp)
        except ACLConflict as exc:
            return exc

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt, candidates))

    successes = [item for item in outcomes if not isinstance(item, ACLConflict)]
    conflicts = [item for item in outcomes if isinstance(item, ACLConflict)]
    assert len(successes) == 1
    assert len(conflicts) == 7
    assert len(ledger.entries) == 1


def test_timeout_after_commit_recovers_original_transaction_and_receipt():
    ledger = ConcurrentFakeLedger(lose_first_post_response=True)
    instance = make_adapter(ledger)
    cp = make_checkpoint()

    result = append(instance, cp)

    assert result.transaction_id == "2.1"
    assert len(ledger.entries) == 1
    assert ledger.lost_response is True
    assert any(
        method == "GET" and path.startswith("/app/transactions?collectionId=")
        for method, path, _body in ledger.calls
    )


def test_replay_after_receipt_timeout_recovers_without_second_commit():
    ledger = ConcurrentFakeLedger()
    instance = make_adapter(ledger)
    cp = make_checkpoint()

    first = append(instance, cp)
    second = append(instance, cp)

    assert first.transaction_id == second.transaction_id == "2.1"
    assert len(ledger.entries) == 1
