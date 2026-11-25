//! Application logos: what an application's tile in My apps shows.
//!
//! An application has an uploaded image, an icon from the built-in library, or
//! neither (the tile shows the initials of its name). Entra's enterprise
//! application *Logo* takes a PNG, JPEG or BMP file under 100 KB; this takes the
//! same. The library is this server's own addition: drawn here, so its icons
//! are inline SVG nobody can upload.
//!
//! An upload is checked by its content, not its file name: it must start as the
//! format it claims and be no larger than [`MAX_IMAGE_BYTES`]. SVG is never
//! accepted as an upload, since an SVG document can carry script.

use crate::db::{Conn, Handle};
use crate::util::now;

/// Entra's limit for an application logo.
pub const MAX_IMAGE_BYTES: usize = 100 * 1024;

/// An uploaded image's format, told by its first bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageType {
    Png,
    Jpeg,
    Bmp,
}

impl ImageType {
    pub const ALL: &'static [ImageType] = &[Self::Png, Self::Jpeg, Self::Bmp];

    /// The media type it is stored and served as.
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Bmp => "image/bmp",
        }
    }

    pub fn parse(content_type: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|t| t.content_type() == content_type)
    }

    /// The signature the file must start with.
    fn magic(self) -> &'static [u8] {
        match self {
            Self::Png => b"\x89PNG\r\n\x1a\n",
            Self::Jpeg => b"\xff\xd8\xff",
            Self::Bmp => b"BM",
        }
    }

    /// The format these bytes are, if any accepted one.
    pub fn sniff(bytes: &[u8]) -> Option<Self> {
        Self::ALL.iter().copied().find(|t| bytes.starts_with(t.magic()))
    }
}

/// An uploaded logo, already checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    pub kind: ImageType,
    pub bytes: Vec<u8>,
}

/// What the administrator is told about a file that cannot be a logo.
pub const NOT_AN_IMAGE: &str = "The logo must be a PNG, JPEG or BMP image.";
pub const EMPTY_FILE: &str = "Choose an image file to upload.";

impl Image {
    /// Check an uploaded file: one of the accepted formats, by its content, and
    /// no larger than Entra allows.
    pub fn from_upload(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err(EMPTY_FILE.into());
        }
        if bytes.len() > MAX_IMAGE_BYTES {
            return Err(format!(
                "The logo must be no larger than {} KB; that file is {} KB.",
                MAX_IMAGE_BYTES / 1024,
                bytes.len().div_ceil(1024)
            ));
        }
        let kind = ImageType::sniff(&bytes).ok_or_else(|| NOT_AN_IMAGE.to_string())?;
        Ok(Self { kind, bytes })
    }
}

/// The icons of the built-in library, each a white line drawing on a colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibraryIcon {
    Chart,
    Mail,
    Calendar,
    Cloud,
    Document,
    Chat,
    Code,
    Shield,
    Cart,
    People,
    Folder,
    Globe,
    Lock,
    Home,
    Book,
    Money,
}

/// One library icon: stored name, what the console calls it, its colour and
/// its drawing (24-unit paths, stroked).
struct IconInfo {
    name: &'static str,
    label: &'static str,
    colour: &'static str,
    path: &'static str,
}

impl LibraryIcon {
    pub const ALL: &'static [LibraryIcon] = &[
        Self::Chart,
        Self::Mail,
        Self::Calendar,
        Self::Cloud,
        Self::Document,
        Self::Chat,
        Self::Code,
        Self::Shield,
        Self::Cart,
        Self::People,
        Self::Folder,
        Self::Globe,
        Self::Lock,
        Self::Home,
        Self::Book,
        Self::Money,
    ];

    fn info(self) -> IconInfo {
        let (name, label, colour, path) = match self {
            Self::Chart => ("chart", "Chart", "#0f6cbd", "M6 18v-7M12 18V6M18 18v-4"),
            Self::Mail => ("mail", "Mail", "#2563eb", "M4 6h16v12H4zM4 7l8 6 8-6"),
            Self::Calendar => ("calendar", "Calendar", "#c2410c", "M5 6h14v13H5zM5 10h14M9 4v4M15 4v4"),
            Self::Cloud => (
                "cloud",
                "Cloud",
                "#0891b2",
                "M7 18h10a4 4 0 0 0 .5-7.97A6 6 0 0 0 6.1 11.1 3.5 3.5 0 0 0 7 18z",
            ),
            Self::Document => (
                "document",
                "Document",
                "#1d4ed8",
                "M7 3h7l4 4v14H7zM14 3v4h4M10 12h5M10 16h5",
            ),
            Self::Chat => ("chat", "Chat", "#7c3aed", "M4 5h16v11H9l-5 4z"),
            Self::Code => ("code", "Code", "#334155", "M9 8l-4 4 4 4M15 8l4 4-4 4"),
            Self::Shield => (
                "shield",
                "Shield",
                "#047857",
                "M12 3l7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6z",
            ),
            Self::Cart => ("cart", "Cart", "#b45309", "M3 4h2l2 11h11l2-8H6M9 20h.01M17 20h.01"),
            Self::People => (
                "people",
                "People",
                "#be185d",
                "M9 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM3 20c0-3 3-5 6-5s6 2 6 5M16 5a3 3 0 0 1 0 6M18 15c2 .5 3 2 3 5",
            ),
            Self::Folder => ("folder", "Folder", "#a16207", "M3 6h6l2 2h10v11H3z"),
            Self::Globe => (
                "globe",
                "Globe",
                "#0e7490",
                "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18",
            ),
            Self::Lock => ("lock", "Lock", "#4d7c0f", "M6 11h12v9H6zM8 11V8a4 4 0 0 1 8 0v3"),
            Self::Home => ("home", "Home", "#9333ea", "M4 11l8-7 8 7v9h-5v-5H9v5H4z"),
            Self::Book => (
                "book",
                "Book",
                "#b91c1c",
                "M4 5c3-1 6-1 8 1 2-2 5-2 8-1v14c-3-1-6-1-8 1-2-2-5-2-8-1zM12 6v14",
            ),
            Self::Money => (
                "money",
                "Money",
                "#15803d",
                "M12 3v18M16 7.5c0-1.5-2-2.5-4-2.5s-4 1-4 2.5 2 2.5 4 3 4 1.5 4 3.5-2 3-4 3-4-1-4-2.5",
            ),
        };
        IconInfo {
            name,
            label,
            colour,
            path,
        }
    }

    pub fn as_str(self) -> &'static str {
        self.info().name
    }

    pub fn label(self) -> &'static str {
        self.info().label
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|i| i.as_str() == raw)
    }

    /// The icon as inline SVG: a rounded square of its colour with the drawing
    /// in white. Decorative: the tile's text names the application.
    pub fn svg(self) -> String {
        let i = self.info();
        format!(
            r##"<svg class="logo" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><rect width="24" height="24" rx="5" fill="{colour}"/><g transform="translate(4.8 4.8) scale(.6)" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="{path}"/></g></svg>"##,
            colour = i.colour,
            path = i.path,
        )
    }
}

/// An application's logo, to set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Logo {
    Library(LibraryIcon),
    Image(Image),
}

/// What a tile shows, without the image's bytes: those are fetched by URL,
/// and `version` changes whenever the image does, so a cached copy is never
/// shown after a new one is uploaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shown {
    Library(LibraryIcon),
    Image { version: i64 },
}

impl Shown {
    /// From a stored row: (library icon, has an image, updated at). A row that
    /// reads as neither (an icon this build no longer draws) shows nothing.
    pub fn from_row(icon: Option<&str>, has_image: bool, updated_at: i64) -> Option<Self> {
        match (icon.and_then(LibraryIcon::parse), has_image) {
            (Some(icon), false) => Some(Self::Library(icon)),
            (None, true) => Some(Self::Image { version: updated_at }),
            _ => None,
        }
    }
}

/// What a logo-less tile shows: up to two initials, from the first letters of
/// the name's first two words.
pub fn initials(name: &str) -> String {
    name.split_whitespace()
        .filter_map(|w| w.chars().find(|c| c.is_alphanumeric()))
        .take(2)
        .flat_map(char::to_uppercase)
        .collect()
}

/// The colour of a logo-less tile: one of the library's, fixed by the
/// application's id so it stays the same from page to page.
pub fn initials_colour(app_id: &str) -> &'static str {
    let sum = app_id
        .bytes()
        .fold(0usize, |acc, b| acc.wrapping_mul(31).wrapping_add(b as usize));
    LibraryIcon::ALL[sum % LibraryIcon::ALL.len()].info().colour
}

/// What the application's tile shows, or `None` for its initials.
pub async fn shown<'c>(db: impl Handle<'c>, application_id: &str) -> anyhow::Result<Option<Shown>> {
    let mut conn = db.acquire().await?;
    shown_in(&mut conn, application_id).await
}

pub(crate) async fn shown_in(conn: &mut Conn, application_id: &str) -> anyhow::Result<Option<Shown>> {
    let row: Option<(Option<String>, Option<String>, i64)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT library_icon, content_type, updated_at FROM app_logos WHERE application_id = ?",
    ))
    .bind(application_id)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.and_then(|(icon, content_type, at)| Shown::from_row(icon.as_deref(), content_type.is_some(), at)))
}

/// The uploaded image, if the application has one. Checked again as it is
/// read, so a row that is not an accepted image is never served.
pub async fn image<'c>(db: impl Handle<'c>, application_id: &str) -> anyhow::Result<Option<Image>> {
    let mut acquired = db.acquire().await?;
    let conn: &mut Conn = &mut acquired;
    let row: Option<(Option<String>, Option<Vec<u8>>)> = sqlx::query_as(crate::db::qc(
        conn,
        "SELECT content_type, image FROM app_logos WHERE application_id = ?",
    ))
    .bind(application_id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((Some(content_type), Some(bytes))) = row else {
        return Ok(None);
    };
    Ok(Image::from_upload(bytes)
        .ok()
        .filter(|i| ImageType::parse(&content_type) == Some(i.kind)))
}

/// Set the application's logo, or remove it with `None`. An image is checked
/// again here, whoever passes it.
pub(crate) async fn set_in(conn: &mut Conn, application_id: &str, logo: Option<&Logo>) -> anyhow::Result<()> {
    sqlx::query(crate::db::qc(conn, "DELETE FROM app_logos WHERE application_id = ?"))
        .bind(application_id)
        .execute(&mut *conn)
        .await?;
    let (icon, content_type, bytes) = match logo {
        None => return Ok(()),
        Some(Logo::Library(icon)) => (Some(icon.as_str()), None, None),
        Some(Logo::Image(image)) => {
            let checked = Image::from_upload(image.bytes.clone()).map_err(anyhow::Error::msg)?;
            anyhow::ensure!(checked.kind == image.kind, NOT_AN_IMAGE);
            (None, Some(image.kind.content_type()), Some(checked.bytes))
        }
    };
    sqlx::query(crate::db::qc(
        conn,
        "INSERT INTO app_logos (application_id, library_icon, content_type, image, updated_at) VALUES (?, ?, ?, ?, ?)",
    ))
    .bind(application_id)
    .bind(icon)
    .bind(content_type)
    .bind(bytes)
    .bind(now())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";

    #[test]
    fn an_upload_is_judged_by_its_content_and_size() {
        assert_eq!(Image::from_upload(PNG.to_vec()).unwrap().kind, ImageType::Png);
        assert_eq!(
            Image::from_upload(b"\xff\xd8\xff\xe0".to_vec()).unwrap().kind,
            ImageType::Jpeg
        );
        assert_eq!(Image::from_upload(b"BM\0\0".to_vec()).unwrap().kind, ImageType::Bmp);
        // SVG, which can carry script, and anything else: refused.
        for refused in [&b"<svg xmlns='http://www.w3.org/2000/svg'/>"[..], b"GIF89a", b"hello"] {
            assert_eq!(Image::from_upload(refused.to_vec()).unwrap_err(), NOT_AN_IMAGE);
        }
        assert_eq!(Image::from_upload(Vec::new()).unwrap_err(), EMPTY_FILE);
        let mut big = PNG.to_vec();
        big.resize(MAX_IMAGE_BYTES, 0);
        assert!(Image::from_upload(big.clone()).is_ok());
        big.push(0);
        assert!(Image::from_upload(big).unwrap_err().contains("100 KB"));
    }

    #[test]
    fn every_library_icon_reads_back_by_name() {
        for icon in LibraryIcon::ALL {
            assert_eq!(LibraryIcon::parse(icon.as_str()), Some(*icon));
            assert!(icon.svg().starts_with("<svg"));
        }
        assert_eq!(LibraryIcon::parse("nope"), None);
    }

    #[test]
    fn initials_come_from_the_first_two_words() {
        assert_eq!(initials("Payroll"), "P");
        assert_eq!(initials("expense   tracker app"), "ET");
        assert_eq!(initials("(beta) portal"), "BP");
        assert_eq!(initials(""), "");
    }
}
