"""Gate 3.2A witness-first authority regression tests (Class A)."""
import pytest

from cybershield_ml.release_anchor import WitnessedReleaseStateStore
from cybershield_ml.release_witness import WitnessCheckpoint

SCOPE = {"tenant_id": "tenant-a", "deployment_id": "deployment-a", "product": "CyberShield"}

def checkpoint(sequence=45, version="0.3.45"):
    return WitnessCheckpoint(
        **SCOPE, release_sequence=sequence, release_version=version,
        metadata_sha256="1" * 64, artifact_sha256="2" * 64,
        publisher_key_id="publisher-1", publisher_signature_sha256="3" * 64,
        previous_checkpoint_sha256=None, operation_id=f"op-{sequence}",
    )

class FakeWitness:
    def __init__(self, current=None):
        self.current = current
        self.calls = []
    def read_checkpoint(self, **_scope):
        self.calls.append("read")
        return (self.current, object()) if self.current else None
    def verify_receipt(self, *, checkpoint, receipt):
        self.calls.append("verify")
        if self.current is None or checkpoint.checkpoint_sha256 != self.current.checkpoint_sha256:
            raise ValueError("receipt checkpoint mismatch")
    def compare_and_append(self, *, expected_previous_checkpoint_sha256, checkpoint):
        self.calls.append("append")
        actual = self.current.checkpoint_sha256 if self.current else None
        if actual != expected_previous_checkpoint_sha256:
            raise RuntimeError("compare-and-append conflict")
        self.current = checkpoint
        return object()

class FakeAnchor:
    def __init__(self, floor=None):
        self.floor = floor
    def read_floor(self, **_scope):
        return self.floor
    def advance_floor(self, *, release_sequence, version, **_scope):
        self.floor = (release_sequence, version)

class FakeDatabase:
    def __init__(self, floor=None):
        self.floor = floor
    def get_release(self, **_scope):
        return self.floor
    def accept_release(self, *, release_sequence, version, **_scope):
        self.floor = (release_sequence, version)

def kwargs(sequence=1, version="0.3.1", operation="candidate-1"):
    return {
        **SCOPE, "release_sequence": sequence, "version": version,
        "metadata_sha256": "1" * 64, "artifact_sha256": "2" * 64,
        "publisher_key_id": "publisher-1", "publisher_signature_sha256": "3" * 64,
        "operation_id": operation,
    }

def test_witness_append_and_receipt_verification_precede_mirror_advancement():
    witness, anchor, db = FakeWitness(), FakeAnchor(), FakeDatabase()
    store = WitnessedReleaseStateStore(witness=witness, anchor=anchor, database_store=db)
    store.accept_release(**kwargs())
    assert witness.calls.index("append") < witness.calls.index("verify")
    assert anchor.floor == db.floor == (1, "0.3.1")

def test_lagging_mirrors_heal_forward_from_witness_before_next_append():
    current = checkpoint()
    witness = FakeWitness(current)
    anchor, db = FakeAnchor((40, "0.3.40")), FakeDatabase((40, "0.3.40"))
    store = WitnessedReleaseStateStore(witness=witness, anchor=anchor, database_store=db)
    store.accept_release(**kwargs(46, "0.3.46", "op-46"))
    assert anchor.floor == db.floor == (46, "0.3.46")
    assert witness.current.release_sequence == 46

@pytest.mark.parametrize("ahead", ["anchor", "database"])
def test_mirror_ahead_of_witness_fails_closed(ahead):
    witness = FakeWitness(checkpoint())
    anchor = FakeAnchor((46, "0.3.46") if ahead == "anchor" else (45, "0.3.45"))
    db = FakeDatabase((46, "0.3.46") if ahead == "database" else (45, "0.3.45"))
    store = WitnessedReleaseStateStore(witness=witness, anchor=anchor, database_store=db)
    with pytest.raises(RuntimeError, match="ahead of independent witness"):
        store.accept_release(**kwargs(46, "0.3.46", "op-46"))

def test_mirror_without_witness_fails_closed():
    store = WitnessedReleaseStateStore(
        witness=FakeWitness(), anchor=FakeAnchor((40, "0.3.40")),
        database_store=FakeDatabase((40, "0.3.40")),
    )
    with pytest.raises(RuntimeError, match="witness is unprovisioned"):
        store.accept_release(**kwargs())

def test_invalid_receipt_prevents_mirror_mutation():
    class InvalidWitness(FakeWitness):
        def verify_receipt(self, **_kwargs):
            raise ValueError("receipt invalid")
    anchor, db = FakeAnchor(), FakeDatabase()
    store = WitnessedReleaseStateStore(witness=InvalidWitness(), anchor=anchor, database_store=db)
    with pytest.raises(ValueError, match="receipt invalid"):
        store.accept_release(**kwargs())
    assert anchor.floor is None and db.floor is None
