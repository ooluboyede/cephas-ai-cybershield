-- DIRMC 0.4.5 PostgreSQL reference schema.
-- Apply with a customer-controlled migration role; runtime role must not own these tables.
CREATE TABLE IF NOT EXISTS dirmc_device_fraud_associations (
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    product_id TEXT NOT NULL,
    business_unit_id TEXT NOT NULL DEFAULT '',
    device_key TEXT NOT NULL CHECK (device_key ~ '^hmac-sha256:v[1-9][0-9]*:[a-f0-9]{64}$'),
    case_id TEXT NOT NULL,
    association_status TEXT NOT NULL CHECK (association_status IN ('suspected','confirmed','cleared')),
    evidence_ref TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    record_json JSONB NOT NULL,
    PRIMARY KEY (tenant_id, deployment_id, environment, product_id, business_unit_id, device_key, case_id)
);
CREATE INDEX IF NOT EXISTS idx_dirmc_device_lookup
ON dirmc_device_fraud_associations
(tenant_id, deployment_id, environment, product_id, business_unit_id, device_key, occurred_at);

CREATE TABLE IF NOT EXISTS dirmc_device_association_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    product_id TEXT NOT NULL,
    business_unit_id TEXT NOT NULL DEFAULT '',
    device_key TEXT NOT NULL,
    case_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action = 'association_inserted'),
    record_sha256 CHAR(64) NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION dirmc_reject_audit_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'DIRMC audit records are append-only';
END;
$$;
DROP TRIGGER IF EXISTS dirmc_audit_no_update ON dirmc_device_association_audit;
CREATE TRIGGER dirmc_audit_no_update BEFORE UPDATE ON dirmc_device_association_audit
FOR EACH ROW EXECUTE FUNCTION dirmc_reject_audit_mutation();
DROP TRIGGER IF EXISTS dirmc_audit_no_delete ON dirmc_device_association_audit;
CREATE TRIGGER dirmc_audit_no_delete BEFORE DELETE ON dirmc_device_association_audit
FOR EACH ROW EXECUTE FUNCTION dirmc_reject_audit_mutation();

-- Bind database login principals to authorised scopes. Provision rows only with
-- the migration/admin identity. The application runtime role must have no write access.
CREATE TABLE IF NOT EXISTS dirmc_runtime_principal_scope (
    db_role NAME NOT NULL,
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    product_id TEXT NOT NULL,
    business_unit_id TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (db_role, tenant_id, deployment_id, environment, product_id, business_unit_id)
);

CREATE OR REPLACE FUNCTION dirmc_principal_scope_authorized(
    p_tenant TEXT, p_deployment TEXT, p_environment TEXT,
    p_product TEXT, p_business_unit TEXT
) RETURNS BOOLEAN
LANGUAGE SQL STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $dirmc$
    SELECT EXISTS (
        SELECT 1 FROM public.dirmc_runtime_principal_scope s
        WHERE s.db_role = session_user
          AND s.tenant_id = p_tenant
          AND s.deployment_id = p_deployment
          AND s.environment = p_environment
          AND s.product_id = p_product
          AND s.business_unit_id = p_business_unit
    );
$dirmc$;
REVOKE ALL ON FUNCTION dirmc_principal_scope_authorized(TEXT,TEXT,TEXT,TEXT,TEXT) FROM PUBLIC;

ALTER TABLE dirmc_device_fraud_associations ENABLE ROW LEVEL SECURITY;
ALTER TABLE dirmc_device_fraud_associations FORCE ROW LEVEL SECURITY;
ALTER TABLE dirmc_device_association_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE dirmc_device_association_audit FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS dirmc_association_scope ON dirmc_device_fraud_associations;
CREATE POLICY dirmc_association_scope ON dirmc_device_fraud_associations
USING (
 tenant_id = current_setting('cephas.tenant_id', true)
 AND deployment_id = current_setting('cephas.deployment_id', true)
 AND environment = current_setting('cephas.environment', true)
 AND product_id = ANY(string_to_array(current_setting('cephas.allowed_products', true), ','))
 AND business_unit_id = COALESCE(NULLIF(current_setting('cephas.business_unit_id', true), ''), '')
 AND dirmc_principal_scope_authorized(tenant_id, deployment_id, environment, product_id, business_unit_id)
)
WITH CHECK (
 tenant_id = current_setting('cephas.tenant_id', true)
 AND deployment_id = current_setting('cephas.deployment_id', true)
 AND environment = current_setting('cephas.environment', true)
 AND product_id = ANY(string_to_array(current_setting('cephas.allowed_products', true), ','))
 AND business_unit_id = COALESCE(NULLIF(current_setting('cephas.business_unit_id', true), ''), '')
 AND dirmc_principal_scope_authorized(tenant_id, deployment_id, environment, product_id, business_unit_id)
);

DROP POLICY IF EXISTS dirmc_audit_scope ON dirmc_device_association_audit;
CREATE POLICY dirmc_audit_scope ON dirmc_device_association_audit
USING (
 tenant_id = current_setting('cephas.tenant_id', true)
 AND deployment_id = current_setting('cephas.deployment_id', true)
 AND environment = current_setting('cephas.environment', true)
 AND product_id = ANY(string_to_array(current_setting('cephas.allowed_products', true), ','))
 AND business_unit_id = COALESCE(NULLIF(current_setting('cephas.business_unit_id', true), ''), '')
 AND dirmc_principal_scope_authorized(tenant_id, deployment_id, environment, product_id, business_unit_id)
)
WITH CHECK (
 tenant_id = current_setting('cephas.tenant_id', true)
 AND deployment_id = current_setting('cephas.deployment_id', true)
 AND environment = current_setting('cephas.environment', true)
 AND product_id = ANY(string_to_array(current_setting('cephas.allowed_products', true), ','))
 AND business_unit_id = COALESCE(NULLIF(current_setting('cephas.business_unit_id', true), ''), '')
 AND dirmc_principal_scope_authorized(tenant_id, deployment_id, environment, product_id, business_unit_id)
);

-- Provision a non-owner runtime role separately. Grant SELECT/INSERT on associations;
-- grant SELECT/INSERT on audit only. Do not grant UPDATE/DELETE/TRUNCATE/DDL or BYPASSRLS.


-- Admin provisioning example (replace values; never grant runtime access to this table):
-- INSERT INTO dirmc_runtime_principal_scope
-- (db_role, tenant_id, deployment_id, environment, product_id, business_unit_id)
-- VALUES ('dirmc_tenant_a_runtime', 'tenant-a', 'deployment-a', 'prod',
--         'cybershield', 'business-unit-a');
-- GRANT EXECUTE ON FUNCTION dirmc_principal_scope_authorized(TEXT,TEXT,TEXT,TEXT,TEXT)
-- TO dirmc_tenant_a_runtime;
-- Use a distinct login principal for each authorised tenant/deployment/BU/product
-- boundary, or an authenticated database proxy that establishes an equivalent
-- non-spoofable session_user identity. GUCs alone are not an authorization boundary.
