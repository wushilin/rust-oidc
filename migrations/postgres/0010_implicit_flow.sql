-- Entra gates the implicit and hybrid response types per app registration, off by
-- default ("ID tokens" and "access tokens" under Implicit grant and hybrid flows;
-- manifest oauth2AllowIdTokenImplicitFlow / oauth2AllowImplicitFlow). Tokens delivered
-- through the front channel land in browser history and Referer headers, so this must be
-- something an app opts into deliberately, like allow_password_grant (0005).
ALTER TABLE applications ADD COLUMN allow_id_token_implicit BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE applications ADD COLUMN allow_access_token_implicit BOOLEAN NOT NULL DEFAULT FALSE;
