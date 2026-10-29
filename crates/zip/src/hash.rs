//! Looking up entries by name: the rules of `zip_hash.c`, on the standard
//! library's `HashMap`, which hashes with SipHash-1-3 and random keys as
//! libzip 1.12 does.

use std::collections::HashMap;

use crate::error::{Error, ErrorCode, Result};

/// The name as libzip's table keys it: a C string, which ends at its first
/// NUL byte.
pub(crate) fn c_string(name: &[u8]) -> &[u8] {
    match name.iter().position(|&b| b == 0) {
        Some(end) => &name[..end],
        None => name,
    }
}

/// `zip_hash_t`, for an archive as it was read: each name, and the index
/// of the first entry with it.
#[derive(Default)]
pub(crate) struct Names {
    table: HashMap<Vec<u8>, u64>,
}

impl Names {
    /// `_zip_hash_reserve_capacity`.
    pub(crate) fn reserve_capacity(&mut self, capacity: usize) {
        let _ = self.table.try_reserve(capacity);
    }

    /// Adds `name` for entry `index`, or fails with `ZIP_ER_EXISTS` if an
    /// entry has it already: port of `_zip_hash_add` with
    /// `ZIP_FL_UNCHANGED`.
    pub(crate) fn add(&mut self, name: &[u8], index: u64) -> Result<()> {
        let name = c_string(name);
        if self.table.contains_key(name) {
            return Err(Error::new(ErrorCode::Exists, 0));
        }
        self.table.insert(name.to_vec(), index);
        Ok(())
    }

    /// The index of the entry named `name`: port of `_zip_hash_lookup`.
    pub(crate) fn lookup(&self, name: &[u8]) -> Result<u64> {
        self.table
            .get(c_string(name))
            .copied()
            .ok_or(Error::new(ErrorCode::NoEntry, 0))
    }
}
