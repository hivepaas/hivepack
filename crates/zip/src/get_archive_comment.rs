//! Port of `zip_get_archive_comment.c`.

use crate::open::Archive;
use crate::source::ReadAt;
use crate::string::string_get;
use crate::zip::Flags;

impl<R: ReadAt> Archive<R> {
    /// The archive comment, converted as names are, or nothing: port of
    /// `zip_get_archive_comment`. A torrentzipped archive has none.
    pub fn get_archive_comment(&self, flags: Flags) -> &[u8] {
        string_get(self.comment_orig.as_ref(), flags)
    }
}
