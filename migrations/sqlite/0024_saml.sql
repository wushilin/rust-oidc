-- Enterprise SAML single sign-on, following Entra's model.

-- Where the application's own sign-in starts (Entra's "Sign on URL"). The app
-- gallery links here when it is set, so that launch is SP-initiated.
ALTER TABLE applications ADD COLUMN sign_on_url TEXT;

-- Entra's preferredSingleSignOnMode ('saml', or NULL when none was chosen), and
-- whether the application is listed in the user's app gallery.
ALTER TABLE service_principals ADD COLUMN preferred_sso_mode TEXT;
ALTER TABLE service_principals ADD COLUMN visible_to_users INTEGER NOT NULL DEFAULT 1;

-- Basic SAML Configuration and signing options, one row per SAML application.
CREATE TABLE app_saml_settings (
    application_id           TEXT PRIMARY KEY,
    tenant_id                TEXT NOT NULL,
    relay_state              TEXT,
    logout_url               TEXT,
    name_id_format           TEXT NOT NULL,
    name_id_source           TEXT NOT NULL,
    signing_option           TEXT NOT NULL,
    signing_algorithm        TEXT NOT NULL,
    require_signed_requests  INTEGER NOT NULL DEFAULT 0,
    encryption_cert_b64      TEXT,
    created_at               INTEGER NOT NULL,
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Identifier (Entity ID) values. Unique in the tenant: a request names its
-- application by one of them.
CREATE TABLE app_saml_identifiers (
    application_id  TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    entity_id       TEXT NOT NULL,
    is_default      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (application_id, entity_id),
    UNIQUE (tenant_id, entity_id),
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Reply URLs (Assertion Consumer Service). `url_index` answers a request's
-- AssertionConsumerServiceIndex.
CREATE TABLE app_saml_reply_urls (
    application_id  TEXT NOT NULL,
    url             TEXT NOT NULL,
    url_index       INTEGER NOT NULL,
    is_default      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (application_id, url),
    UNIQUE (application_id, url_index),
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);

-- Token signing certificates. Each application has its own, because SAML apps
-- pin them by hand. At most one is active (enforced by the storage layer).
CREATE TABLE app_saml_certificates (
    id               TEXT PRIMARY KEY,
    application_id   TEXT NOT NULL,
    private_key_pem  TEXT NOT NULL,
    cert_b64         TEXT NOT NULL,
    thumbprint       TEXT NOT NULL,
    not_after        INTEGER NOT NULL,
    active           INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL,
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);
CREATE INDEX app_saml_certificates_app ON app_saml_certificates(application_id);

-- Public certificates that verify an application's signed requests.
CREATE TABLE app_saml_verification_certs (
    id              TEXT PRIMARY KEY,
    application_id  TEXT NOT NULL,
    cert_b64        TEXT NOT NULL,
    thumbprint      TEXT NOT NULL,
    not_after       INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    UNIQUE (application_id, thumbprint),
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);

-- Attributes & Claims: the attribute name and which user property fills it.
CREATE TABLE app_saml_claims (
    application_id  TEXT NOT NULL,
    name            TEXT NOT NULL,
    source          TEXT NOT NULL,
    PRIMARY KEY (application_id, name),
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);

-- Which applications a browser session signed in to, for Single Logout.
CREATE TABLE saml_session_participants (
    session_index   TEXT PRIMARY KEY,
    session_hash    TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    application_id  TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    name_id         TEXT NOT NULL,
    name_id_key     TEXT NOT NULL,
    name_id_format  TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    UNIQUE (session_hash, application_id, user_id, name_id_key),
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX saml_session_participants_session ON saml_session_participants(session_hash);

-- A Single Logout in progress, keyed by the id of the request awaiting an answer.
CREATE TABLE saml_logout_state (
    request_id   TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    pending_app  TEXT NOT NULL,
    browser_hash TEXT NOT NULL,
    remaining    TEXT NOT NULL,
    finish       TEXT NOT NULL,
    expires_at   INTEGER NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- A launch from the app gallery: single-use, for one user and one application.
CREATE TABLE saml_launch_tickets (
    ticket_hash     TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    application_id  TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    expires_at      INTEGER NOT NULL,
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Ids of signed messages already acted on, so none can be replayed.
CREATE TABLE saml_seen_messages (
    application_id  TEXT NOT NULL,
    message_id      TEXT NOT NULL,
    expires_at      INTEGER NOT NULL,
    PRIMARY KEY (application_id, message_id),
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);
