//! Port of `zip_add_entry.c`.

use crate::open::Archive;
use crate::source::ReadAt;
use crate::zipint::Entry;

impl<R: ReadAt> Archive<R> {
    /// A new entry at the end, with nothing yet: port of `_zip_add_entry`.
    pub(crate) fn add_entry(&mut self) -> u64 {
        self.entry.push(Entry::default());
        self.entry.len() as u64 - 1
    }
}
