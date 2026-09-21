ALTER TABLE email_accounts ADD COLUMN IF NOT EXISTS provider_subscription_id VARCHAR(255);
ALTER TABLE email_accounts ADD COLUMN IF NOT EXISTS provider_subscription_expires_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_email_accounts_subscription ON email_accounts(provider_subscription_id);