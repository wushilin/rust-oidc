-- Keep the logout continuation at the IdP while the browser visits the app.
ALTER TABLE saml_logout_state ADD COLUMN next_url TEXT;
ALTER TABLE saml_logout_state ADD COLUMN resume_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE saml_logout_state ADD COLUMN answer_success BOOLEAN;

-- Maintenance removes expired protocol state in batches.
CREATE INDEX saml_session_participants_expiry ON saml_session_participants(expires_at);
CREATE INDEX saml_seen_messages_expiry ON saml_seen_messages(expires_at);
CREATE INDEX saml_launch_tickets_expiry ON saml_launch_tickets(expires_at);
CREATE INDEX saml_logout_state_expiry ON saml_logout_state(expires_at);
CREATE INDEX saml_logout_state_browser ON saml_logout_state(browser_hash, expires_at);
