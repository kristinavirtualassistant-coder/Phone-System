ALTER TABLE communication_contacts ADD COLUMN IF NOT EXISTS consent_status VARCHAR(16) NOT NULL DEFAULT 'UNKNOWN' CHECK (consent_status IN ('UNKNOWN','OPTED_IN','OPTED_OUT'));
ALTER TABLE communication_contacts ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS idx_comm_contacts_consent ON communication_contacts(tenant_id, consent_status);