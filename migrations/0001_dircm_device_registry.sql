-- DIRCM 0.1 tenant-scoped device identity registry.
-- Apply using a customer-controlled migration principal. Application roles must
-- not own these tables and must not have BYPASSRLS.
"
CREATE TABLE IF NOT EXISTS dircm_devices (
    tenant_id TEXT NOT NULL,
    device_id UUID NOT NULL,
    lifecycle_state TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (lifecycle_state IN ('ACTIVE', 'RETIRED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, device_id)
);

CREATE TABLE IF NOT EXISTS dircm_verified_identifiers (
    tenant_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    identifier_type TEXT NOT NULL,
    identifier_digest CHAR(64) NOT NULL
        CHECK (identifier_digest ~ '^[0-9a-f]{64}$'),
    device_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, source_id, identifier_type, identifier_digest),
    FOREIGN KEY (tenant_id, device_id)
        REFERENCES dircm_devices (tenant_id, device_id)
);

CREATE TABLE IF NOT EXISTS dircm_match_candidates (
    tenant_id TEXT NOT NULL,
    candidate_id UUID NOT NULL,
    source_id TEXT NOT NULL,
    identifier_type TEXT NOT NULL,
    identifier_digest CHAR(64) NOT NULL
        CHECK (identifier_digest ~ '^[0-9a-f]{64}$'),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'CONFIRMED', 'REJECTED', 'EXPIRED')),
    PRIMARY KEY (tenant_id, candidate_id),
    UNIQUE (tenant_id, source_id, identifier_type, identifier_digest)
);

ALTER TABLE dircm_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE dircm_devices FORCE ROW LEVEL SECURITY;
ALTER TABLE dircm_verified_identifiers ENABLE ROW LEVEL SECURITY;
ALTER TABLE dircm_verified_identifiers FORCE ROW LEVEL SECURITY;
ALTER TABLE dircm_match_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE dircm_match_candidates FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS dircm_devices_tenant_policy ON dircm_devices;
CREATE POLICY dircm_devices_tenant_policy ON dircm_devices
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS dircm_verified_identifiers_tenant_policy ON dircm_verified_identifiers;
CREATE POLICY dircm_verified_identifiers_tenant_policy ON dircm_verified_identifiers
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS dircm_match_candidates_tenant_policy ON dircm_match_candidates;
CREATE POLICY dircm_match_candidates_tenant_policy ON dircm_match_candidates
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
