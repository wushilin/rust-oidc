//! Doing one thing to many rows at once.
//!
//! A list page puts a tick box on each row and one in the heading that means
//! "all of them", and its buttons act on whatever is ticked. There is no script:
//! the boxes and buttons belong to one form by the `form` attribute, so they can
//! sit in a table that also holds links, and the heading box is an ordinary
//! field the server reads as "every row this page listed".
//!
//! Each row still goes through the same storage function a single change would,
//! with its own rules and its own audit entry. Some may be refused while others
//! succeed; the page then says how many were done and which were not, and why.

use crate::admin::view::e;

/// One ticked row: its id.
pub const ITEM: &str = "item";
/// The heading box: every row the page listed.
pub const ALL: &str = "all";
/// The box that must be ticked beside a button that deletes.
pub const CONFIRM: &str = "confirm";

/// What was ticked.
pub struct Selection {
    all: bool,
    items: Vec<String>,
    pub confirmed: bool,
}

impl Selection {
    pub fn read(body: &[u8]) -> Self {
        let mut out = Self {
            all: false,
            items: Vec::new(),
            confirmed: false,
        };
        for (key, value) in url::form_urlencoded::parse(body) {
            match key.as_ref() {
                ALL => out.all = true,
                CONFIRM => out.confirmed = true,
                ITEM if !out.items.iter().any(|i| i == value.as_ref()) => out.items.push(value.into_owned()),
                _ => {}
            }
        }
        out
    }

    /// The ticked rows among `listed`, in the page's order. Only what the page
    /// listed can be chosen, so a posted id from somewhere else selects nothing.
    pub fn among<'a, T>(&self, listed: &'a [T], id: impl Fn(&T) -> &str) -> Vec<&'a T> {
        listed
            .iter()
            .filter(|row| self.all || self.items.iter().any(|i| i == id(row)))
            .collect()
    }
}

pub const NOTHING_TICKED: &str = "Tick the rows to change, or the box in the heading for all of them.";
pub const NOT_CONFIRMED: &str = "Tick \u{201c}confirm\u{201d} beside the delete button to delete what is selected.";

/// What became of each row.
#[derive(Default)]
pub struct Tally {
    pub done: usize,
    refused: Vec<(String, String)>,
}

impl Tally {
    pub fn refuse(&mut self, what: &str, why: impl std::fmt::Display) {
        self.refused.push((what.to_string(), why.to_string()));
    }

    /// `None` when every row was done; otherwise what to tell the administrator.
    pub fn problem(&self, done_as: &str) -> Option<String> {
        if self.refused.is_empty() {
            return None;
        }
        let mut out = format!("{} {done_as}. Not changed: ", self.done);
        let each: Vec<String> = self
            .refused
            .iter()
            .map(|(what, why)| format!("{what} ({why})"))
            .collect();
        out.push_str(&each.join("; "));
        Some(out)
    }
}

/// The heading cell: the box for all rows.
pub fn head(form: &str) -> String {
    format!(
        r#"<th class="tick"><input type="checkbox" class="all" name="{ALL}" form="{form}" aria-label="All rows"></th>"#,
        form = e(form)
    )
}

/// A row's cell: the box for that row.
pub fn cell(form: &str, id: &str, label: &str) -> String {
    format!(
        r#"<td class="tick"><input type="checkbox" class="row" name="{ITEM}" value="{id}" form="{form}" aria-label="{label}"></td>"#,
        form = e(form),
        id = e(id),
        label = e(label),
    )
}

/// The confirm box that goes beside a delete button.
pub fn confirm(form: &str) -> String {
    format!(
        r#"<label class="confirm"><input type="checkbox" name="{CONFIRM}" form="{form}"> confirm</label>"#,
        form = e(form)
    )
}
