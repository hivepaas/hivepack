//! Port of `zip_fopen_index.c`.

use crate::error::Result;
use crate::fopen_index_encrypted::ZipFile;
use crate::open::Archive;
use crate::source::ReadAt;
use crate::zip::Flags;

impl<R: ReadAt> Archive<R> {
    /// Opens entry `index` for reading: port of `zip_fopen_index`.
    ///
    /// The data is decompressed, unless `flags` has [`Flags::COMPRESSED`],
    /// and the CRC-32 and length of an entry read to its end are checked.
    /// Stored, deflated and Deflate64 entries are read for now (libzip
    /// reads no Deflate64); others fail with
    /// [`ErrorCode::CompNotSupp`](crate::ErrorCode::CompNotSupp), and
    /// encrypted ones with [`ErrorCode::NoPasswd`](crate::ErrorCode::NoPasswd).
    /// Several entries may be open at once, each reading at its own
    /// position.
    pub fn fopen_index(&self, index: u64, flags: Flags) -> Result<ZipFile<'_, R>> {
        // The archive has no default password: zip_set_default_password
        // comes with decryption.
        self.fopen_index_encrypted(index, flags, None)
    }
}
