//! Port of `zip_file_set_encryption.c`.

use crate::dirent::Dirent;
use crate::error::{Error, ErrorCode, Result};
use crate::get_encryption_implementation::encryption_method_supported;
use crate::open::Archive;
use crate::zip::em;
use crate::zipint::{Password, changed};

impl<R> Archive<R> {
    /// Encrypts entry `idx` with `method` ([`em::NONE`] for none) when the
    /// archive is written, with `password`, or the default password if
    /// `None`: port of `zip_file_set_encryption`. An empty password is one,
    /// and works with ZipCrypto; WinZip AES refuses it when writing. The
    /// password is taken up to its first NUL byte, as libzip takes a C
    /// string.
    ///
    /// [`em::NONE`]: crate::em::NONE
    pub fn file_set_encryption(
        &mut self,
        idx: u64,
        method: u16,
        password: Option<&[u8]>,
    ) -> Result<()> {
        if idx >= self.entry.len() as u64 {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        if self.is_rdonly() {
            return Err(Error::new(ErrorCode::RdOnly, 0));
        }
        if self.want_torrentzip() {
            return Err(Error::new(ErrorCode::NotAllowed, 0));
        }
        if method != em::NONE && !encryption_method_supported(method, true) {
            return Err(Error::new(ErrorCode::EncrNotSupp, 0));
        }

        let e = &mut self.entry[idx as usize];
        let orig_password = e.orig.as_ref().and_then(|o| o.password.clone());
        let changes = e
            .changes
            .get_or_insert_with(|| Box::new(Dirent::clone_changes(e.orig.as_deref())));
        changes.encryption_method = method;
        changes.changed |= changed::ENCRYPTION_METHOD;
        match password {
            Some(password) => {
                changes.password = Some(Password::new(password));
                changes.changed |= changed::PASSWORD;
            }
            None => {
                changes.password = orig_password;
                changes.changed &= !changed::PASSWORD;
            }
        }
        Ok(())
    }
}
