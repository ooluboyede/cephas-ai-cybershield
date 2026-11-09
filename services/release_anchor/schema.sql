-- Execute as a customer-controlled database owner, not the runtime service role.
CREATE TABLE IF NOT EXISTS cephas_release_floor (
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    product TEXT NOT NULL,
    release_sequence BIGINT NOT NULL CHECK (release_sequence >= 1),
    version TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, deployment_id, product)
);

CREATE TABLE IF NOT EXISTS cephas_release_floor_audit (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    client_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    product TEXT NOT NULL,
    release_sequence BIGINT NOT NULL CHECK (release_sequence >= 1),
    version TEXT NOT NULL
);

-- Replace the role name with the customer-created, least-privilege service role.
-- Do not grant UPDATE/DELETE/TRUNCATE on the audit table to the runtime role.
REVOKE ALL ON cephas_release_floor, cephas_release_floor_audit FROM PUBLIC;
-- GRANT SELECT, INSERT, UPDATE ON cephas_release_floor TO cephas_anchor_runtime;
-- GRANT INSERT ON cephas_release_floor_audit TO cephas_anchor_runtime;
-- GRANT USAGE, SELECT ON SEQUENCE cephas_release_floor_audit_event_id_seq TO cephas_anchor_runtime;
