"""Azure Confidential Ledger provider adapter (Phase 2 Gate 2.3).

The adapter deliberately keeps Azure credentials and network access outside the
provider-neutral witness protocol. A caller supplies a short-lived bearer-token
provider. The adapter never creates or trusts a service certificate dynamically:
the service identity certificate must be pinned out-of-band by the customer.

This module is an implementation candidate. A live customer-controlled ACL
ledger is still required to validate the deployed UDF, RBAC, hooks and API
behavior before production use.
"""
from __future__ import annotations

import hashlib
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from .release_witness import WitnessCheckpoint


API_VERSION = "2026-02-23"
DEFAULT_UDF_ID = "cephasReleaseWitnessCompareAndAppend"


class ACLProviderError(RuntimeError):
    """Base class for fail-closed Azure Confidential Ledger adapter errors."""


class ACLUnavailable(ACLProviderError):
    """The adapter could not establish a committed, verified outcome."""


class ACLProtocolError(ACLProviderError):
    """The provider response did not satisfy the expected contract."""


class ACLConflict(ACLProviderError):
    """The UDF rejected a stale, conflicting, or unauthorized append."""


class JSONTransport(Protocol):
    def request_json(self, method: str, path: str, body: dict | None = None) -> dict:
        """Perform an authenticated JSON request against the pinned ACL endpoint."""


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "ACL redirects are forbidden", headers, fp)


class ACLHTTPSJSONTransport:
    """Small HTTPS transport with explicit TLS trust and bearer-token injection."""

    def __init__(
        self,
        *,
        endpoint: str,
        token_provider: Callable[[], str],
        service_certificate_path: str,
        timeout_seconds: float = 10.0,
        api_version: str = API_VERSION,
    ) -> None:
        parsed = urllib.parse.urlparse(endpoint)
        if parsed.scheme != "https" or not parsed.netloc or parsed.path not in ("", "/"):
            raise ValueError("ACL endpoint must be an HTTPS origin")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("ACL endpoint must not contain credentials, query or fragment")
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ValueError("timeout_seconds must be in (0, 60]")
        if not api_version or any(ch not in "0123456789.-preview" for ch in api_version):
            raise ValueError("invalid ACL API version")
        self._origin = f"https://{parsed.netloc}"
        self._token_provider = token_provider
        self._timeout = timeout_seconds
        self._api_version = api_version
        self._ssl_context = ssl.create_default_context(cafile=service_certificate_path)
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self._ssl_context),
            _RejectRedirects(),
        )

    def request_json(self, method: str, path: str, body: dict | None = None) -> dict:
        if not path.startswith("/") or "://" in path or ".." in path:
            raise ValueError("ACL path must be an absolute service-relative path")
        parsed_path = urllib.parse.urlsplit(path)
        query_items = urllib.parse.parse_qsl(parsed_path.query, keep_blank_values=True)
        query_items.append(("api-version", self._api_version))
        query = urllib.parse.urlencode(query_items)
        url = f"{self._origin}{parsed_path.path}?{query}"
        token = self._token_provider()
        if not isinstance(token, str) or not token.strip():
            raise ACLProviderError("token provider returned an empty bearer token")
        data = None if body is None else json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                raw = response.read(2_000_001)
                if len(raw) > 2_000_000:
                    raise ACLProtocolError("ACL response exceeded the 2 MB safety limit")
                parsed = json.loads(raw.decode("utf-8"))
                if not isinstance(parsed, dict):
                    raise ACLProtocolError("ACL returned a non-object JSON response")
                return parsed
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace")
            if exc.code in (409, 412):
                raise ACLConflict(f"ACL rejected compare-and-append ({exc.code})") from exc
            raise ACLProviderError(f"ACL HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise ACLUnavailable("ACL request failed; commit outcome is not assumed") from exc


@dataclass(frozen=True)
class ACLAppendResult:
    transaction_id: str
    receipt_response: dict
    application_claims: list[dict]


def _canonical_checkpoint_claim(checkpoint: WitnessCheckpoint) -> dict:
    canonical = checkpoint.canonical_bytes()
    return {
        "schema": "cephas.cybershield.acl-witness-claims.v2",
        "checkpoint_sha256": hashlib.sha256(canonical).hexdigest(),
        "checkpoint_canonical_utf8": canonical.decode("utf-8"),
        "operation_id": checkpoint.operation_id,
        "tenant_id": checkpoint.tenant_id,
        "deployment_id": checkpoint.deployment_id,
        "product": checkpoint.product,
        "udf_id": DEFAULT_UDF_ID,
        "contract_version": "0.3.5",
    }


class AzureConfidentialLedgerAdapter:
    """ACL adapter for a customer-provisioned ledger and reviewed UDF.

    The caller must provide an independently authenticated identity whose ACL
    permissions are limited to the required application operations. Scope must
    be derived by the service authentication layer; this adapter does not accept
    an untrusted caller-supplied scope override.
    """

    def __init__(
        self,
        *,
        transport: JSONTransport,
        service_identity_certificate_pem: str,
        udf_id: str = DEFAULT_UDF_ID,
        expected_udf_sha256: str,
        collection_id: str = "cephas-release-witness-v2",
        commit_poll_attempts: int = 20,
        receipt_poll_attempts: int = 20,
        poll_interval_seconds: float = 1.0,
        native_receipt_verifier: Callable | None = None,
    ) -> None:
        if not service_identity_certificate_pem.strip():
            raise ValueError("out-of-band pinned ACL service identity certificate is required")
        if not udf_id or len(udf_id) > 128:
            raise ValueError("invalid UDF id")
        if len(expected_udf_sha256) != 64 or any(
            c not in "0123456789abcdef" for c in expected_udf_sha256
        ):
            raise ValueError("expected_udf_sha256 must be lowercase SHA-256 hex")
        if commit_poll_attempts < 1 or receipt_poll_attempts < 1:
            raise ValueError("poll attempts must be positive")
        if poll_interval_seconds < 0 or poll_interval_seconds > 30:
            raise ValueError("poll interval must be between 0 and 30 seconds")
        self._transport = transport
        self._service_cert = service_identity_certificate_pem
        self._udf_id = udf_id
        self._udf_sha256 = expected_udf_sha256
        self._collection_id = collection_id
        self._commit_attempts = commit_poll_attempts
        self._receipt_attempts = receipt_poll_attempts
        self._poll_interval = poll_interval_seconds
        self._native_receipt_verifier = native_receipt_verifier

    def _verify_deployed_udf(self) -> None:
        response = self._transport.request_json(
            "GET", f"/app/userDefinedFunctions/{urllib.parse.quote(self._udf_id, safe='')}"
        )
        code = response.get("code")
        if not isinstance(code, str):
            raise ACLProtocolError("deployed ACL UDF response did not contain code")
        actual = hashlib.sha256(code.encode("utf-8")).hexdigest()
        if actual != self._udf_sha256:
            raise ACLProtocolError("deployed ACL UDF digest differs from the pinned code digest")

    def _get_committed_receipt(self, transaction_id: str) -> dict:
        status_path = f"/app/transactions/{urllib.parse.quote(transaction_id, safe='')}/status"
        committed = False
        for attempt in range(self._commit_attempts):
            status = self._transport.request_json("GET", status_path)
            state = status.get("state")
            if state == "Committed":
                committed = True
                break
            if state not in ("Pending", "Loading"):
                raise ACLProtocolError(f"unexpected ACL transaction state: {state!r}")
            if attempt + 1 < self._commit_attempts:
                time.sleep(self._poll_interval)
        if not committed:
            raise ACLUnavailable("ACL transaction did not reach Committed; no acknowledgement issued")

        receipt_path = f"/app/transactions/{urllib.parse.quote(transaction_id, safe='')}/receipt"
        for attempt in range(self._receipt_attempts):
            response = self._transport.request_json("GET", receipt_path)
            if response.get("state") == "Ready":
                if response.get("transactionId") != transaction_id:
                    raise ACLProtocolError("receipt transaction ID does not match requested transaction")
                return response
            if response.get("state") != "Loading":
                raise ACLProtocolError("ACL receipt response is not Ready or Loading")
            if attempt + 1 < self._receipt_attempts:
                time.sleep(self._poll_interval)
        raise ACLUnavailable("ACL receipt remained Loading; no acknowledgement issued")

    def append(
        self,
        checkpoint: WitnessCheckpoint,
        *,
        expected_previous_checkpoint_sha256: str | None,
    ) -> ACLAppendResult:
        if expected_previous_checkpoint_sha256 != checkpoint.previous_checkpoint_sha256:
            raise ValueError("expected predecessor must equal the checkpoint predecessor")
        claim = _canonical_checkpoint_claim(checkpoint)
        claim["udf_id"] = self._udf_id
        claim["udf_sha256"] = self._udf_sha256
        claim["contract_version"] = "0.3.5"
        contents = {
            "record_type": "cephas-release-witness-checkpoint-v2",
            "checkpoint": checkpoint.as_dict(),
            "checkpoint_sha256": checkpoint.checkpoint_sha256,
            "operation_id": checkpoint.operation_id,
            "udf_id": self._udf_id,
            "udf_sha256": self._udf_sha256,
            "contract_version": "0.3.5",
        }
        self._verify_deployed_udf()
        response = self._transport.request_json(
            "POST",
            f"/app/transactions?collectionId={urllib.parse.quote(self._collection_id, safe='')}",
            {
                "contents": json.dumps(contents, sort_keys=True, separators=(",", ":")),
                "preHooks": [{"functionId": self._udf_id}],
                "applicationClaims": [claim],
            },
        )
        transaction_id = response.get("transactionId")
        if not isinstance(transaction_id, str) or not transaction_id:
            raise ACLProtocolError("ACL write response did not contain transactionId")
        receipt = self._get_committed_receipt(transaction_id)
        self.verify_native_receipt(
            receipt,
            service_identity_certificate_pem=self._service_cert,
            application_claims=[claim],
            native_receipt_verifier=self._native_receipt_verifier,
        )
        return ACLAppendResult(
            transaction_id=transaction_id,
            receipt_response=receipt,
            application_claims=[claim],
        )

    @staticmethod
    def verify_native_receipt(
        receipt_response: dict,
        *,
        service_identity_certificate_pem: str,
        application_claims: list[dict],
        native_receipt_verifier: Callable | None = None,
    ) -> None:
        """Verify using Microsoft's offline ACL receipt verifier.

        Install the optional Azure SDK extra in the customer environment. The
        verifier performs Merkle proof, signing-node endorsement and claims-digest
        verification without contacting Azure.
        """
        if native_receipt_verifier is None:
            try:
                from azure.confidentialledger.receipt import verify_receipt
            except ImportError as exc:
                raise ACLProviderError(
                    "install azure-confidentialledger to verify native ACL receipts"
                ) from exc
            native_receipt_verifier = verify_receipt
        if receipt_response.get("state") != "Ready":
            raise ACLProtocolError("cannot verify an uncommitted or Loading receipt")
        native_receipt = receipt_response.get("receipt")
        if not isinstance(native_receipt, dict):
            raise ACLProtocolError("receipt response has no native CCF receipt")
        leaf = native_receipt.get("leafComponents")
        if not isinstance(leaf, dict) or not leaf.get("writeSetDigest") or not leaf.get("claimsDigest"):
            raise ACLProtocolError("native receipt is missing writeSetDigest or claimsDigest")
        native_receipt_verifier(
            native_receipt,
            service_identity_certificate_pem,
            application_claims=application_claims,
        )
