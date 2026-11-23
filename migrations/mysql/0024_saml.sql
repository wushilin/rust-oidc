-- Enterprise SAML single sign-on, following Entra's model.

-- Where the application's own sign-in starts (Entra's "Sign on URL"). The app
-- gallery links here when it is set, so that launch is SP-initiated.
ALTER TABLE applications ADD COLUMN sign_on_url TEXT COLLATE utf8mb4_bin;

-- Entra's preferredSingleSignOnMode ('saml', or NULL when none was chosen), and
-- whether the application is listed in the user's app gallery.
ALTER TABLE service_principals ADD COLUMN preferred_sso_mode VARCHAR(32) COLLATE utf8mb4_bin;
ALTER TABLE service_principals ADD COLUMN visible_to_users SMALLINT NOT NULL DEFAULT 1;

-- Basic SAML Configuration and signing options, one row per SAML application.
CREATE TABLE app_saml_settings (
    application_id           VARCHAR(64) COLLATE utf8mb4_bin PRIMARY KEY,
    tenant_id                VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    relay_state              TEXT COLLATE utf8mb4_bin,
    logout_url               TEXT COLLATE utf8mb4_bin,
    name_id_format           VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
    name_id_source           VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
    signing_option           VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
    signing_algorithm        VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
    require_signed_requests  SMALLINT NOT NULL DEFAULT 0,
    encryption_cert_b64      TEXT COLLATE utf8mb4_bin,
    created_at               BIGINT NOT NULL,
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Identifier (Entity ID) values. Unique in the tenant: a request names its
-- application by one of them.
CREATE TABLE app_saml_identifiers (
    application_id  VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    tenant_id       VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    entity_id       VARCHAR(512) COLLATE utf8mb4_bin NOT NULL,
    is_default      SMALLINT NOT NULL DEFAULT 0,
    PRIMARY KEY (application_id, entity_id),
    UNIQUE (tenant_id, entity_id),
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Reply URLs (Assertion Consumer Service). `url_index` answers a request's
-- AssertionConsumerServiceIndex.
CREATE TABLE app_saml_reply_urls (
    application_id  VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    url             VARCHAR(512) COLLATE utf8mb4_bin NOT NULL,
    url_index       BIGINT NOT NULL,
    is_default      SMALLINT NOT NULL DEFAULT 0,
    PRIMARY KEY (application_id, url),
    UNIQUE (application_id, url_index),
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);

-- Token signing certificates. Each application has its own, because SAML apps
-- pin them by hand. At most one is active (enforced by the storage layer).
CREATE TABLE app_saml_certificates (
    id               VARCHAR(64) COLLATE utf8mb4_bin PRIMARY KEY,
    application_id   VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    private_key_pem  TEXT COLLATE utf8mb4_bin NOT NULL,
    cert_b64         TEXT COLLATE utf8mb4_bin NOT NULL,
    thumbprint       VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
    not_after        BIGINT NOT NULL,
    active           SMALLINT NOT NULL DEFAULT 0,
    created_at       BIGINT NOT NULL,
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);
CREATE INDEX app_saml_certificates_app ON app_saml_certificates(application_id);

-- Public certificates that verify an application's signed requests.
CREATE TABLE app_saml_verification_certs (
    id              VARCHAR(64) COLLATE utf8mb4_bin PRIMARY KEY,
    application_id  VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    cert_b64        TEXT COLLATE utf8mb4_bin NOT NULL,
    thumbprint      VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
    not_after       BIGINT NOT NULL,
    created_at      BIGINT NOT NULL,
    UNIQUE (application_id, thumbprint),
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);

-- Attributes & Claims: the attribute name and which user property fills it.
CREATE TABLE app_saml_claims (
    application_id  VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    name            VARCHAR(512) COLLATE utf8mb4_bin NOT NULL,
    source          VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
    PRIMARY KEY (application_id, name),
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);

-- Which applications a browser session signed in to, for Single Logout.
CREATE TABLE saml_session_participants (
    session_index   VARCHAR(128) COLLATE utf8mb4_bin PRIMARY KEY,
    session_hash    VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
    tenant_id       VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    application_id  VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    user_id         VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    name_id         TEXT COLLATE utf8mb4_bin NOT NULL,
    name_id_key     VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
    name_id_format  VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
    created_at      BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,
    UNIQUE (session_hash, application_id, user_id, name_id_key),
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX saml_session_participants_session ON saml_session_participants(session_hash);

-- A Single Logout in progress, keyed by the id of the request awaiting an answer.
CREATE TABLE saml_logout_state (
    request_id   VARCHAR(128) COLLATE utf8mb4_bin PRIMARY KEY,
    tenant_id    VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    pending_app  VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
    browser_hash VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
    remaining    TEXT COLLATE utf8mb4_bin NOT NULL,
    finish       TEXT COLLATE utf8mb4_bin NOT NULL,
    expires_at   BIGINT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- A launch from the app gallery: single-use, for one user and one application.
CREATE TABLE saml_launch_tickets (
    ticket_hash     VARCHAR(128) COLLATE utf8mb4_bin PRIMARY KEY,
    tenant_id       VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    application_id  VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    user_id         VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    expires_at      BIGINT NOT NULL,
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Ids of signed messages already acted on, so none can be replayed.
CREATE TABLE saml_seen_messages (
    application_id  VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
    message_id      VARCHAR(512) COLLATE utf8mb4_bin NOT NULL,
    expires_at      BIGINT NOT NULL,
    PRIMARY KEY (application_id, message_id),
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);
