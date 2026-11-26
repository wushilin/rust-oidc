-- Ties a browser sign-in's second step to the authorization request it began
-- with, so a ticket cannot finish a different request (one asking for a fresh
-- sign-in, say). Empty for steps outside that flow, and for tickets already
-- waiting when this applies: those just ask the user to sign in again.
ALTER TABLE mfa_pending ADD COLUMN request_hash VARCHAR(64) NOT NULL DEFAULT '';
