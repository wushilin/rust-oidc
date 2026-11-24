-- How each application's assertions are encrypted. Applications set up before
-- the choice existed keep what they had, which is what Entra sends: AES-256-CBC
-- with the key wrapped by RSA-OAEP-MGF1P over SHA-1. New ones are given the
-- recommended choice when SAML is enabled.
ALTER TABLE app_saml_settings ADD COLUMN encryption_method TEXT NOT NULL DEFAULT 'aes256-cbc';
ALTER TABLE app_saml_settings ADD COLUMN key_transport TEXT NOT NULL DEFAULT 'rsa-oaep-mgf1p';
ALTER TABLE app_saml_settings ADD COLUMN key_transport_digest TEXT NOT NULL DEFAULT 'sha1';
