// CEPHAS CyberShield ACL pre-hook — Gate 2.3 candidate.
 // This source is deployed as the UDF identified by DEFAULT_UDF_ID.
 // ACL UDF hooks are per-request: the ACL REST API requires each POST
 // /app/transactions request to name this function in preHooks.
 // Do not claim that installing this UDF automatically hooks every write.
export function main() {
    const fail = (message) => { throw new Error("CEPHAS_WITNESS_REJECTED:" + message); };
    const text = (value) => ccf.bufToStr(value);
    const bytes = (value) => ccf.strToBuf(value);
    const parse = (value, label) => {
        try { return JSON.parse(value); } catch (_) { fail("invalid_" + label); }
    };
    const stable = (value) => {
        if (Array.isArray(value)) return "[" + value.map(stable).join(",") + "]";
        if (value !== null && typeof value === "object") {
            return "{" + Object.keys(value).sort().map(
                (key) => JSON.stringify(key) + ":" + stable(value[key])
            ).join(",") + "}";
        }
        if (typeof value === "number" && !Number.isSafeInteger(value)) fail("non_integer_number");
        return JSON.stringify(value);
    };
    const hex = (buffer) => Array.from(new Uint8Array(buffer))
        .map((value) => value.toString(16).padStart(2, "0")).join("");

    const payload = parse(context.contents, "transaction_contents");
    if (!payload || payload.record_type !== "cephas-release-witness-checkpoint-v2") {
        fail("wrong_record_type");
    }
    if (payload.contract_version !== "0.3.5" || payload.udf_id !== "cephasReleaseWitnessCompareAndAppend") {
        fail("wrong_contract_or_udf");
    }
    if (typeof payload.udf_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(payload.udf_sha256)) {
        fail("invalid_udf_digest");
    }

    const cp = payload.checkpoint;
    const expectedFields = [
        "artifact_sha256", "deployment_id", "metadata_sha256", "operation_id",
        "previous_checkpoint_sha256", "product", "protocol", "protocol_version",
        "publisher_key_id", "publisher_signature_sha256", "release_sequence",
        "release_version", "tenant_id"
    ].sort();
    if (!cp || Object.keys(cp).sort().join("|") !== expectedFields.join("|")) {
        fail("checkpoint_field_set_mismatch");
    }
    if (cp.protocol !== "cephas.cybershield.release-witness" || cp.protocol_version !== "1") {
        fail("unsupported_checkpoint_protocol");
    }
    if (!Number.isSafeInteger(cp.release_sequence) || cp.release_sequence < 1) fail("invalid_sequence");
    for (const field of ["tenant_id", "deployment_id", "product", "release_version", "operation_id"]) {
        if (typeof cp[field] !== "string" || cp[field].length < 1 || cp[field].trim() !== cp[field]) {
            fail("invalid_" + field);
        }
    }
    for (const field of ["metadata_sha256", "artifact_sha256", "publisher_signature_sha256"]) {
        if (typeof cp[field] !== "string" || !/^[0-9a-f]{64}$/.test(cp[field])) fail("invalid_" + field);
    }
    if (cp.previous_checkpoint_sha256 !== null &&
        (typeof cp.previous_checkpoint_sha256 !== "string" ||
         !/^[0-9a-f]{64}$/.test(cp.previous_checkpoint_sha256))) {
        fail("invalid_predecessor");
    }

    if (payload.operation_id !== cp.operation_id) fail("operation_id_mismatch");
    if (context.collectionId !== "cephas-release-witness-v2") fail("wrong_collection");
    const canonical = stable(cp);
    const canonicalDigest = hex(ccf.crypto.digest("SHA-256", bytes(canonical)));
    if (payload.checkpoint_sha256 !== canonicalDigest) fail("checkpoint_digest_mismatch");

    // Scope comes from the authenticated ACL principal, never request fields.
    const principal = context.userId;
    if (typeof principal !== "string" || !principal) fail("missing_authenticated_principal");
    const principalBytes = ccf.kv["public:release_witness_principals"].get(bytes(principal));
    if (principalBytes === undefined) fail("principal_not_provisioned");
    const authorized = parse(text(principalBytes), "principal_scope");
    if (authorized.tenant_id !== cp.tenant_id ||
        authorized.deployment_id !== cp.deployment_id ||
        authorized.product !== cp.product) fail("scope_denied");

    const scope = JSON.stringify([cp.tenant_id, cp.deployment_id, cp.product]);
    const headTable = ccf.kv["public:release_witness_heads"];
    const opTable = ccf.kv["public:release_witness_operations"];
    const checkpointTable = ccf.kv["public:release_witness_checkpoints"];
    const operationKey = scope + "|" + cp.operation_id;
    const operationBytes = opTable.get(bytes(operationKey));
    if (operationBytes !== undefined) {
        const previousOperation = parse(text(operationBytes), "operation_index");
        if (previousOperation.checkpoint_sha256 === canonicalDigest) {
            fail("IDEMPOTENT_RETRY_LOOKUP_REQUIRED");
        }
        fail("OPERATION_ID_CONFLICT");
    }

    const headBytes = headTable.get(bytes(scope));
    let expectedSequence = 1;
    let expectedPrevious = null;
    if (headBytes !== undefined) {
        const head = parse(text(headBytes), "scope_head");
        expectedSequence = head.release_sequence + 1;
        expectedPrevious = head.checkpoint_sha256;
    }
    if (cp.release_sequence !== expectedSequence) fail("STALE_OR_SKIPPED_SEQUENCE");
    if (cp.previous_checkpoint_sha256 !== expectedPrevious) fail("PREDECESSOR_MISMATCH");

    const checkpointKey = scope + "|" + cp.release_sequence;
    if (checkpointTable.get(bytes(checkpointKey)) !== undefined) fail("SEQUENCE_ALREADY_EXISTS");
    const operationRecord = {
        checkpoint_sha256: canonicalDigest,
        release_sequence: cp.release_sequence,
        operation_id: cp.operation_id,
        transaction_id: null
    };
    const headRecord = {
        release_sequence: cp.release_sequence,
        checkpoint_sha256: canonicalDigest,
        operation_id: cp.operation_id
    };
    checkpointTable.set(bytes(checkpointKey), bytes(canonical));
    opTable.set(bytes(operationKey), bytes(JSON.stringify(operationRecord)));
    headTable.set(bytes(scope), bytes(JSON.stringify(headRecord)));
}
