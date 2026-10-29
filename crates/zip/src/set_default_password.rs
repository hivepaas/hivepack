//! Port of `zip_set_default_password.c`.

use crate::hash::c_string;
use crate::open::Archive;

impl<R> Archive<R> {
    /// Sets the password that encrypted entries are read with when none is
    /// given, or removes it with `None` or an empty password: port of
    /// `zip_set_default_password`. The password is taken up to its first
    /// NUL byte, as libzip takes a C string.
    ///
    /// Differs from libzip, which cannot fail here but for memory: it
    /// returns nothing.
    pub fn set_default_password(&mut self, passwd: Option<&[u8]>) {
        if let Some(old) = self.default_password.as_mut() {
            old.fill(0);
            std::hint::black_box(old);
        }
        self.default_password = passwd
            .map(c_string)
            .filter(|p| !p.is_empty())
            .map(<[u8]>::to_vec);
    }
}
