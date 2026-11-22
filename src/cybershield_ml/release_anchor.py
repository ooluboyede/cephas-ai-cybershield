"""Customer-operated HTTPS release-floor anchor client and fail-closed composition.

The remote service is the recovery authority. PostgreSQL is an operational mirror.
This module never falls back to PostgreSQL when the HTTPS anchor is unavailable.
"""

import json
import ssl
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class ReleaseFloorAnchor(Protocol):
    def read_floor(self, *, tenant_id: str, deployment_id: str, product: str):
        """Return (sequence, version), or None when the anchor has no floor."""
        ...

    def advance_floor(
        self, *, tenant_id: str, deployment_id: str, product: str,
        release_sequence: int, version: str
    ) -> None:
        """Atomically advance; reject stale/conflicting values."""
        ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpReleaseFloorAnchor:
    """HTTPS client for a customer-operated release-floor authority.

    TLS certificate verification and mutual TLS client authentication are mandatory.
    The bearer token must also be scoped by the service to permitted deployments.
    """

    def __init__(
        self,
        base_url: str,
        bearer_token: str,
        *,
        ca_bundle: str | None = None,
        client_cert: str | None = None,
        client_key: str | None = None,
        timeout: float = 5.0,
    ):
        parsed = urlsplit(base_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("release-floor anchor URL must be an HTTPS origin/path without query")
        if not bearer_token or not bearer_token.strip():
            raise ValueError("a scoped release-floor anchor bearer token is required")
        if not client_cert or not client_key:
            raise ValueError("mutual TLS client_cert and client_key are required")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._base_url = base_url.rstrip("/")
        self._token = bearer_token
        self._timeout = timeout
        context = ssl.create_default_context(cafile=ca_bundle)
        if client_cert:
            context.load_cert_chain(client_cert, client_key)
        self._opener = build_opener(_NoRedirect(), HTTPSHandler(context=context))

    @staticmethod
    def _path(tenant_id: str, deployment_id: str, product: str) -> str:
        values = (tenant_id, deployment_id, product)
        if not all(isinstance(value, str) and value.strip() for value in values):
            raise ValueError("tenant_id, deployment_id and product must be non-empty strings")
        return "/v1/floors/" + "/".join(quote(value, safe="") for value in values)

    def _request(self, method: str, path: str, payload=None):
        data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        request = Request(
            self._base_url + path,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/json",
                **({"Content-Type": "application/json"} if data is not None else {}),
            },
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                raw = response.read(16_384)
                if len(raw) >= 16_384:
                    raise RuntimeError("release-floor anchor response exceeded size limit")
                return json.loads(raw.decode("utf-8")) if raw else {}
        except HTTPError as exc:
            if method == "GET" and exc.code == 404:
                return None
            if exc.code == 409:
                raise ValueError("release-floor anchor rejected a stale or conflicting release") from exc
            raise RuntimeError(f"release-floor anchor returned HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("release-floor anchor unavailable or returned an invalid response") from exc

    def read_floor(self, *, tenant_id: str, deployment_id: str, product: str):
        payload = self._request("GET", self._path(tenant_id, deployment_id, product))
        if payload is None:
            return None
        if not isinstance(payload, dict):
            raise TypeError("release-floor anchor response must be a JSON object")
        sequence, version = payload.get("release_sequence"), payload.get("version")
        if (
            isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1
            or not isinstance(version, str) or not version.strip()
        ):
            raise RuntimeError("release-floor anchor returned an invalid floor")
        return sequence, version

    def advance_floor(
        self, *, tenant_id: str, deployment_id: str, product: str,
        release_sequence: int, version: str
    ) -> None:
        if isinstance(release_sequence, bool) or not isinstance(release_sequence, int) or release_sequence < 1:
            raise ValueError("release_sequence must be a positive integer")
        if not isinstance(version, str) or not version.strip():
            raise ValueError("version must be a non-empty string")
        self._request(
            "PUT",
            self._path(tenant_id, deployment_id, product),
            {"release_sequence": release_sequence, "version": version},
        )


class AnchoredReleaseStateStore:
    """Anchor-first anti-rollback gate with PostgreSQL reconciliation.

    Anchor advances first. A failed database write is recoverable: the next call
    observes the higher anchor and repairs PostgreSQL forward. A database floor
    ahead of the anchor is ambiguous and therefore blocks model loading.
    """

    def __init__(self, *, anchor: ReleaseFloorAnchor, database_store):
        if anchor is None or database_store is None:
            raise ValueError("both independent anchor and database store are required")
        self._anchor = anchor
        self._database = database_store

    def accept_release(
        self, *, tenant_id: str, deployment_id: str, product: str,
        release_sequence: int, version: str
    ) -> None:
        scope = {"tenant_id": tenant_id, "deployment_id": deployment_id, "product": product}
        anchor_floor = self._anchor.read_floor(**scope)
        database_floor = self._database.get_release(**scope)

        if anchor_floor is None and database_floor is not None:
            raise RuntimeError("database has release state but independent anchor is unprovisioned")
        if anchor_floor is not None:
            if database_floor is not None and database_floor[0] > anchor_floor[0]:
                raise RuntimeError("database release floor is ahead of independent anchor; recovery required")
            if database_floor != anchor_floor:
                self._database.accept_release(
                    **scope, release_sequence=anchor_floor[0], version=anchor_floor[1]
                )
            if (release_sequence, version) == anchor_floor:
                return

        self._anchor.advance_floor(
            **scope, release_sequence=release_sequence, version=version
        )
        self._database.accept_release(
            **scope, release_sequence=release_sequence, version=version
        )




class WitnessedReleaseStateStore:
    """Witness-first anti-rollback authority with forward-only mirror reconciliation."""

    def __init__(self, *, witness, anchor: ReleaseFloorAnchor, database_store):
        if witness is None or anchor is None or database_store is None:
            raise ValueError("independent witness, HTTPS anchor and database store are required")
        for method in ("read_checkpoint", "compare_and_append", "verify_receipt"):
            if not callable(getattr(witness, method, None)):
                raise TypeError(f"witness backend must implement {method}()")
        self._witness, self._anchor, self._database = witness, anchor, database_store

    @staticmethod
    def _scope(*, tenant_id: str, deployment_id: str, product: str) -> dict:
        if not all(isinstance(v, str) and v.strip() for v in (tenant_id, deployment_id, product)):
            raise ValueError("tenant_id, deployment_id and product must be non-empty strings")
        return {"tenant_id": tenant_id, "deployment_id": deployment_id, "product": product}

    def _read_verified_witness(self, scope):
        observed = self._witness.read_checkpoint(**scope)
        if observed is None:
            return None
        if not isinstance(observed, tuple) or len(observed) != 2:
            raise RuntimeError("witness returned an invalid checkpoint/receipt pair")
        checkpoint, receipt = observed
        from .release_witness import WitnessCheckpoint
        if not isinstance(checkpoint, WitnessCheckpoint):
            raise TypeError("witness returned an invalid checkpoint")
        if (checkpoint.tenant_id, checkpoint.deployment_id, checkpoint.product) != (
            scope["tenant_id"], scope["deployment_id"], scope["product"]
        ):
            raise RuntimeError("witness checkpoint scope does not match requested scope")
        self._witness.verify_receipt(checkpoint=checkpoint, receipt=receipt)
        return checkpoint, receipt

    def _reconcile_mirrors(self, scope, checkpoint):
        floor = (checkpoint.release_sequence, checkpoint.release_version)
        anchor_floor = self._anchor.read_floor(**scope)
        database_floor = self._database.get_release(**scope)
        for label, current in (("HTTPS anchor", anchor_floor), ("database", database_floor)):
            if current is not None:
                if not isinstance(current, tuple) or len(current) != 2:
                    raise RuntimeError(f"{label} returned an invalid release floor")
                if current[0] > floor[0]:
                    raise RuntimeError(f"{label} is ahead of independent witness; failing closed")
                if current[0] == floor[0] and current[1] != floor[1]:
                    raise RuntimeError(f"{label} conflicts with independent witness; failing closed")
        if anchor_floor != floor:
            self._anchor.advance_floor(**scope, release_sequence=floor[0], version=floor[1])
        if database_floor != floor:
            self._database.accept_release(**scope, release_sequence=floor[0], version=floor[1])

    def accept_release(
        self, *, tenant_id: str, deployment_id: str, product: str,
        release_sequence: int, version: str, metadata_sha256: str,
        artifact_sha256: str, publisher_key_id: str,
        publisher_signature_sha256: str, operation_id: str,
    ) -> None:
        from .release_witness import WitnessCheckpoint
        scope = self._scope(tenant_id=tenant_id, deployment_id=deployment_id, product=product)
        if isinstance(release_sequence, bool) or not isinstance(release_sequence, int) or release_sequence < 1:
            raise ValueError("release_sequence must be a positive integer")
        if not isinstance(version, str) or not version.strip():
            raise ValueError("version must be a non-empty string")
        current = self._read_verified_witness(scope)
        anchor_floor, database_floor = self._anchor.read_floor(**scope), self._database.get_release(**scope)
        if current is None:
            if anchor_floor is not None or database_floor is not None:
                raise RuntimeError("release mirror exists but independent witness is unprovisioned")
            if release_sequence != 1:
                raise RuntimeError("first witnessed release must be sequence 1")
            previous_digest = None
        else:
            current_checkpoint, _ = current
            self._reconcile_mirrors(scope, current_checkpoint)
            if release_sequence == current_checkpoint.release_sequence:
                if version != current_checkpoint.release_version:
                    raise RuntimeError("release sequence conflicts with independent witness")
                if (
                    metadata_sha256 != current_checkpoint.metadata_sha256
                    or artifact_sha256 != current_checkpoint.artifact_sha256
                    or publisher_key_id != current_checkpoint.publisher_key_id
                    or publisher_signature_sha256 != current_checkpoint.publisher_signature_sha256
                ):
                    raise RuntimeError("same release sequence has different witnessed content")
                return
            if release_sequence != current_checkpoint.release_sequence + 1:
                raise RuntimeError("release sequence must advance exactly one beyond witness")
            previous_digest = current_checkpoint.checkpoint_sha256

        candidate = WitnessCheckpoint(
            tenant_id=tenant_id, deployment_id=deployment_id, product=product,
            release_sequence=release_sequence, release_version=version,
            metadata_sha256=metadata_sha256, artifact_sha256=artifact_sha256,
            publisher_key_id=publisher_key_id,
            publisher_signature_sha256=publisher_signature_sha256,
            previous_checkpoint_sha256=previous_digest, operation_id=operation_id,
        )
        receipt = self._witness.compare_and_append(
            expected_previous_checkpoint_sha256=previous_digest, checkpoint=candidate
        )
        self._witness.verify_receipt(checkpoint=candidate, receipt=receipt)
        observed = self._read_verified_witness(scope)
        if observed is None or observed[0].checkpoint_sha256 != candidate.checkpoint_sha256:
            raise RuntimeError("independent witness did not retain the appended checkpoint")
        self._anchor.advance_floor(**scope, release_sequence=release_sequence, version=version)
        self._database.accept_release(**scope, release_sequence=release_sequence, version=version)
