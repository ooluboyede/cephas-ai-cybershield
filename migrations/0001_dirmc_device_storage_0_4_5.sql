-- DIRMC 0.4.5 PostgreSQL reference schema.
-- Apply using a trusted migration identity. Runtime principals must not own these objects.
-- This migration is intentionally explicit: provision runtime roles and scope rows separately.

CREATE TABLE IF NOT EXISTS public.dirmc_device_fraud_associations (
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    product_id TEXT NOT NULL,
    business_unit_id TEXT NOT NULL DEFAULT '',
    device_key TEXT NOT NULL CHECK (
        device_key ~ '^hmac-sha256:v[1-9][0-9]*:[a-f0-9]{64}$'
    ),
    case_id TEXT NOT NULL,
    association_status TEXT NOT NULL CHECK (
        association_status IN ('suspected', 'confirmed', 'cleared')
    ),
    evidence_ref TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    record_json JSONB NOT NULL,
    record_sha256 CHAR(64) NOT NULL CHECK (record_sha256 ~ '^[a-f0-9]{64}$'),
    PRIMARY KEY (
        tenant_id, deployment_id, environment, product_id,
        business_unit_id, device_key, case_id
    )
);

CREATE INDEX IF NOT EXISTS idx_dirmc_device_lookup
ON public.dirmc_device_fraud_associations (
    tenant_id, deployment_id, environment, product_id,
    business_unit_id, device_key, occurred_at
);

CREATE TABLE IF NOT EXISTS public.dirmc_device_association_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    product_id TEXT NOT NULL,
    business_unit_id TEXT NOT NULL DEFAULT '',
    device_key TEXT NOT NULL,
    case_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action = 'association_inserted'),
    record_sha256 CHAR(64) NOT NULL CHECK (record_sha256 ~ '^[a-f0-9]{64}$'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.dirmc_runtime_principal_scope (
    db_role NAME NOT NULL,
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    product_id TEXT NOT NULL,
    business_unit_id TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (
        db_role, tenant_id, deployment_id, environment, product_id, business_unit_id
    )
);

-- Principal authorization is based on session_user (the authenticated login),
-- not a caller-controlled transaction GUC or SET ROLE identity.
CREATE OR REPLACE FUNCTION public.dirmc_principal_scope_authorized(
    p_tenant TEXT,
    p_deployment TEXT,
    p_environment TEXT,
    p_product TEXT,
    p_business_unit TEXT
) RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $dirmc$
    SELECT EXISTS (
        SELECT 1
        FROM public.dirmc_runtime_principal_scope AS s
        WHERE s.db_role = session_user
          AND s.tenant_id = p_tenant
          AND s.deployment_id = p_deployment
          AND s.environment = p_environment
          AND s.product_id = p_product
          AND s.business_unit_id = p_business_unit
    );
$dirmc$;

REVOKE ALL ON FUNCTION public.dirmc_principal_scope_authorized(TEXT,TEXT,TEXT,TEXT,TEXT)
FROM PUBLIC;

-- The audit trigger is the sole runtime write path to the audit table.
CREATE OR REPLACE FUNCTION public.dirmc_write_association_audit()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $dirmc$
BEGIN
    INSERT INTO public.dirmc_device_association_audit (
        tenant_id, deployment_id, environment, product_id,
        business_unit_id, device_key, case_id, action, record_sha256
    ) VALUES (
        NEW.tenant_id, NEW.deployment_id, NEW.environment, NEW.product_id,
        NEW.business_unit_id, NEW.device_key, NEW.case_id,
        'association_inserted', NEW.record_sha256
    );
    RETURN NEW;
END;
$dirmc$;

REVOKE ALL ON FUNCTION public.dirmc_write_association_audit() FROM PUBLIC;

DROP TRIGGER IF EXISTS dirmc_audit_no_update
ON public.dirmc_device_association_audit;
CREATE TRIGGER dirmc_audit_no_update
BEFORE UPDATE ON public.dirmc_device_association_audit
FOR EACH ROW EXECUTE FUNCTION public.dirmc_reject_audit_mutation();

DROP TRIGGER IF EXISTS dirmc_audit_no_delete
ON public.dirmc_device_association_audit;
CREATE TRIGGER dirmc_audit_no_delete
BEFORE DELETE ON public.dirmc_device_association_audit
FOR EACH ROW EXECUTE FUNCTION public.dirmc_reject_audit_mutation();

DROP TRIGGER IF EXISTS dirmc_association_write_audit
ON public.dirmc_device_fraud_associations;
CREATE TRIGGER dirmc_association_write_audit
AFTER INSERT ON public.dirmc_device_fraud_associations
FOR EACH ROW EXECUTE FUNCTION public.dirmc_write_association_audit();

ALTER TABLE public.dirmc_device_fraud_associations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dirmc_device_fraud_associations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.dirmc_device_association_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dirmc_device_association_audit FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS dirmc_association_scope
ON public.dirmc_device_fraud_associations;
CREATE POLICY dirmc_association_scope
ON public.dirmc_device_fraud_associations
USING (
    tenant_id = current_setting('cephas.tenant_id', true)
    AND deployment_id = current_setting('cephas.deployment_id', true)
    AND environment = current_setting('cephas.environment', true)
    AND product_id = ANY(string_to_array(
        current_setting('cephas.allowed_products', true), ','
    ))
    AND business_unit_id = COALESCE(
        NULLIF(current_setting('cephas.business_unit_id', true), ''), ''
    )
    AND public.dirmc_principal_scope_authorized(
        tenant_id, deployment_id, environment, product_id, business_unit_id
    )
)
WITH CHECK (
    tenant_id = current_setting('cephas.tenant_id', true)
    AND deployment_id = current_setting('cephas.deployment_id', true)
    AND environment = current_setting('cephas.environment', true)
    AND product_id = ANY(string_to_array(
        current_setting('cephas.allowed_products', true), ','
    ))
    AND business_unit_id = COALESCE(
        NULLIF(current_setting('cephas.business_unit_id', true), ''), ''
    )
    AND public.dirmc_principal_scope_authorized(
        tenant_id, deployment_id, environment, product_id, business_unit_id
    )
);

DROP POLICY IF EXISTS dirmc_audit_scope
ON public.dirmc_device_association_audit;
CREATE POLICY dirmc_audit_scope
ON public.dirmc_device_association_audit
USING (
    tenant_id = current_setting('cephas.tenant_id', true)
    AND deployment_id = current_setting('cephas.deployment_id', true)
    AND environment = current_setting('cephas.environment', true)
    AND product_id = ANY(string_to_array(
        current_setting('cephas.allowed_products', true), ','
    ))
    AND business_unit_id = COALESCE(
        NULLIF(current_setting('cephas.business_unit_id', true), ''), ''
    )
    AND public.dirmc_principal_scope_authorized(
        tenant_id, deployment_id, environment, product_id, business_unit_id
    )
)
WITH CHECK (
    tenant_id = current_setting('cephas.tenant_id', true)
    AND deployment_id = current_setting('cephas.deployment_id', true)
    AND environment = current_setting('cephas.environment', true)
    AND product_id = ANY(string_to_array(
        current_setting('cephas.allowed_products', true), ','
    ))
    AND business_unit_id = COALESCE(
        NULLIF(current_setting('cephas.business_unit_id', true), ''), ''
    )
    AND public.dirmc_principal_scope_authorized(
        tenant_id, deployment_id, environment, product_id, business_unit_id
    )
);

-- Required customer-admin provisioning after migration:
-- 1. Ensure the trusted migration identity owns the functions and tables.
-- 2. Create a dedicated LOGIN role for each tenant/deployment/environment/product/BU.
-- 3. Insert its exact scope in dirmc_runtime_principal_scope using the admin identity.
-- 4. Grant EXECUTE on dirmc_principal_scope_authorized to that login.
-- 5. Grant SELECT, INSERT on dirmc_device_fraud_associations.
-- 6. Grant SELECT only on dirmc_device_association_audit (no direct INSERT).
-- 7. Do not grant access to dirmc_runtime_principal_scope, function replacement,
--    schema CREATE, table ownership, BYPASSRLS, TRUNCATE, UPDATE or DELETE.
-- 8. Use a dedicated trusted schema where untrusted principals cannot CREATE objects.
--    These SECURITY DEFINER functions use pg_catalog, pg_temp only and fully-qualified
--    application objects. Their owner must remain a trusted migration identity.
--
-- Example (replace identifiers; execute only as the customer database administrator):
-- INSERT INTO public.dirmc_runtime_principal_scope
-- (db_role, tenant_id, deployment_id, environment, product_id, business_unit_id)
-- VALUES ('dirmc_tenant_a_runtime', 'tenant-a', 'deployment-a', 'prod',
--         'cybershield', 'business-unit-a');
-- GRANT EXECUTE ON FUNCTION public.dirmc_principal_scope_authorized(TEXT,TEXT,TEXT,TEXT,TEXT)
-- TO dirmc_tenant_a_runtime;
-- GRANT SELECT, INSERT ON public.dirmc_device_fraud_associations TO dirmc_tenant_a_runtime;
-- GRANT SELECT ON public.dirmc_device_association_audit TO dirmc_tenant_a_runtime;
-- GRANT USAGE, SELECT ON SEQUENCE public.dirmc_device_association_audit_audit_id_seq
-- TO dirmc_tenant_a_runtime;
