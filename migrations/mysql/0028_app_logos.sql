-- An application's logo, shown on its tile in My apps: an uploaded image, or an
-- icon from the built-in library (by name). One of the two, never both; the
-- storage layer keeps it so. No row: the tile shows the name's initials.
-- MEDIUMBLOB: an image may be 100 KB, over BLOB's 64 KB.
CREATE TABLE app_logos (
    application_id  VARCHAR(64) COLLATE utf8mb4_bin PRIMARY KEY,
    library_icon    VARCHAR(64) COLLATE utf8mb4_bin,
    content_type    VARCHAR(64) COLLATE utf8mb4_bin,
    image           MEDIUMBLOB,
    updated_at      BIGINT NOT NULL,
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);
