-- An application's logo, shown on its tile in My apps: an uploaded image, or an
-- icon from the built-in library (by name). One of the two, never both; the
-- storage layer keeps it so. No row: the tile shows the name's initials.
CREATE TABLE app_logos (
    application_id  TEXT PRIMARY KEY,
    library_icon    TEXT,
    content_type    TEXT,
    image           BLOB,
    updated_at      INTEGER NOT NULL,
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);
