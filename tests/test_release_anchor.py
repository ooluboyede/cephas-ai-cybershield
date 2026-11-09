import pytest

from cybershield_ml.release_anchor import AnchoredReleaseStateStore, HttpReleaseFloorAnchor


class MemoryAnchor:
    def __init__(self, floor=None):
        self.floor = floor
        self.available = True

    def read_floor(self, **_):
        if not self.available:
            raise RuntimeError("anchor unavailable")
        return self.floor

    def advance_floor(self, *, release_sequence, version, **_):
        if not self.available:
            raise RuntimeError("anchor unavailable")
        candidate = (release_sequence, version)
        if self.floor and (
            release_sequence < self.floor[0]
            or (release_sequence == self.floor[0] and version != self.floor[1])
        ):
            raise ValueError("stale or conflicting anchor floor")
        if self.floor is None or release_sequence > self.floor[0]:
            self.floor = candidate


class MemoryDatabase:
    def __init__(self, floor=None, fail_write=False):
        self.floor = floor
        self.fail_write = fail_write

    def get_release(self, **_):
        return self.floor

    def accept_release(self, *, release_sequence, version, **_):
        if self.fail_write:
            raise RuntimeError("database write unavailable")
        candidate = (release_sequence, version)
        if self.floor and (
            release_sequence < self.floor[0]
            or (release_sequence == self.floor[0] and version != self.floor[1])
        ):
            raise ValueError("stale or conflicting database floor")
        if self.floor is None or release_sequence > self.floor[0]:
            self.floor = candidate


SCOPE = {
    "tenant_id": "tenant-a",
    "deployment_id": "deployment-a",
    "product": "CEPHAS AI CyberShield",
}


def test_restore_from_old_database_backup_is_reconciled_to_anchor_floor():
    anchor = MemoryAnchor((45, "0.3.45"))
    database = MemoryDatabase((40, "0.3.40"))
    store = AnchoredReleaseStateStore(anchor=anchor, database_store=database)

    store.accept_release(**SCOPE, release_sequence=45, version="0.3.45")

    assert database.floor == (45, "0.3.45")
    assert anchor.floor == (45, "0.3.45")


def test_database_ahead_of_anchor_fails_closed_without_auto_promoting_anchor():
    anchor = MemoryAnchor((45, "0.3.45"))
    database = MemoryDatabase((46, "0.3.46"))
    store = AnchoredReleaseStateStore(anchor=anchor, database_store=database)

    with pytest.raises(RuntimeError, match="ahead of independent anchor"):
        store.accept_release(**SCOPE, release_sequence=47, version="0.3.47")

    assert anchor.floor == (45, "0.3.45")
    assert database.floor == (46, "0.3.46")


def test_database_state_without_anchor_requires_explicit_bootstrap():
    anchor = MemoryAnchor(None)
    database = MemoryDatabase((40, "0.3.40"))
    store = AnchoredReleaseStateStore(anchor=anchor, database_store=database)

    with pytest.raises(RuntimeError, match="anchor is unprovisioned"):
        store.accept_release(**SCOPE, release_sequence=41, version="0.3.41")


def test_anchor_unavailable_fails_closed_before_database_access():
    anchor = MemoryAnchor((45, "0.3.45"))
    anchor.available = False
    database = MemoryDatabase((45, "0.3.45"))
    store = AnchoredReleaseStateStore(anchor=anchor, database_store=database)

    with pytest.raises(RuntimeError, match="anchor unavailable"):
        store.accept_release(**SCOPE, release_sequence=46, version="0.3.46")


def test_anchor_advance_then_database_failure_recovers_forward_on_retry():
    anchor = MemoryAnchor((45, "0.3.45"))
    database = MemoryDatabase((45, "0.3.45"), fail_write=True)
    store = AnchoredReleaseStateStore(anchor=anchor, database_store=database)

    with pytest.raises(RuntimeError, match="database write unavailable"):
        store.accept_release(**SCOPE, release_sequence=46, version="0.3.46")

    assert anchor.floor == (46, "0.3.46")
    assert database.floor == (45, "0.3.45")

    database.fail_write = False
    store.accept_release(**SCOPE, release_sequence=46, version="0.3.46")
    assert database.floor == (46, "0.3.46")


def test_stale_candidate_is_rejected_and_never_lowers_either_floor():
    anchor = MemoryAnchor((45, "0.3.45"))
    database = MemoryDatabase((45, "0.3.45"))
    store = AnchoredReleaseStateStore(anchor=anchor, database_store=database)

    with pytest.raises(ValueError, match="stale or conflicting"):
        store.accept_release(**SCOPE, release_sequence=44, version="0.3.44")

    assert anchor.floor == (45, "0.3.45")
    assert database.floor == (45, "0.3.45")


def test_http_anchor_rejects_plain_http_and_unscoped_empty_token():
    with pytest.raises(ValueError, match="HTTPS"):
        HttpReleaseFloorAnchor("http://anchor.internal", "secret")
    with pytest.raises(ValueError, match="bearer token"):
        HttpReleaseFloorAnchor("https://anchor.internal", " ")
