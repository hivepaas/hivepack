//! The decompressing and compressing layers: port of
//! `zip_source_compress.c`, with deflate its only algorithm for now.

use crate::algorithm_deflate::{
    CompressionStatus, DeflateCompress, DeflateDecompress, VERSION_NEEDED,
};
use crate::dirent::{CM_DEFAULT, cm_actual};
use crate::error::{Detail, Error, ErrorCode, Result};
use crate::source_data::{FileAttributes, GENERAL_PURPOSE_BIT_FLAGS_ALLOWED_MASK, file_attributes};
use crate::zip::{Stat, cm, stat};

/// `BUFSIZE`.
const BUFSIZE: usize = 8192;

/// `struct context`, for decompressing.
pub(crate) struct Decompress {
    pub(crate) error: Error,
    end_of_input: bool,
    end_of_stream: bool,
    check_consistency: bool,
    size: u64,
    first_read: i64,
    buffer: Box<[u8; BUFSIZE]>,
    algorithm: DeflateDecompress,
}

/// The decompressing algorithm for `method`, if libzip has one: port of
/// `_zip_get_compression_algorithm`, for decompressing. Differs from
/// libzip, which is often built with bzip2, LZMA, XZ and Zstandard: those
/// come with their crates; and libzip has no Deflate64, which is read here.
pub(crate) fn get_compression_algorithm(method: u16) -> Option<DeflateDecompress> {
    match method {
        cm::DEFLATE => Some(DeflateDecompress::new(false)),
        cm::DEFLATE64 => Some(DeflateDecompress::new(true)),
        _ => None,
    }
}

/// Whether `method` can be used, to compress or to decompress: port of
/// `zip_compression_method_supported`.
pub(crate) fn compression_method_supported(method: i32, compress: bool) -> bool {
    if method == i32::from(cm::STORE) {
        return true;
    }
    let real_method = cm_actual(method);
    if compress {
        real_method == cm::DEFLATE
    } else {
        get_compression_algorithm(real_method).is_some()
    }
}

/// `ZIP_SOURCE_GET_FILE_ATTRIBUTES` of a compression layer: the version
/// needed for the algorithm, and the general purpose bits it sets, all of
/// the allowed ones decided here.
fn compression_attributes(general_purpose_bit_flags: u16) -> FileAttributes {
    FileAttributes {
        valid: file_attributes::VERSION_NEEDED | file_attributes::GENERAL_PURPOSE_BIT_FLAGS,
        version_needed: VERSION_NEEDED,
        general_purpose_bit_mask: GENERAL_PURPOSE_BIT_FLAGS_ALLOWED_MASK,
        general_purpose_bit_flags,
        ..FileAttributes::default()
    }
}

impl Decompress {
    /// `ZIP_SOURCE_GET_FILE_ATTRIBUTES`: no general purpose bits, as
    /// decompressing sets none.
    pub(crate) fn file_attributes(&self) -> FileAttributes {
        compression_attributes(0)
    }

    /// Port of `context_new` for decompressing; `None` if `method` has no
    /// algorithm (`compression_source_new` fails with
    /// `ZIP_ER_COMPNOTSUPP`).
    pub(crate) fn new(method: u16, check_consistency: bool) -> Result<Decompress> {
        let Some(algorithm) = get_compression_algorithm(method) else {
            return Err(Error::new(ErrorCode::CompNotSupp, 0));
        };
        Ok(Decompress {
            error: Error::OK,
            end_of_input: false,
            end_of_stream: false,
            check_consistency,
            size: 0,
            first_read: -1,
            buffer: Box::new([0; BUFSIZE]),
            algorithm,
        })
    }

    /// `ZIP_SOURCE_OPEN`.
    pub(crate) fn open(&mut self) -> Result<()> {
        self.size = 0;
        self.end_of_input = false;
        self.end_of_stream = false;
        self.first_read = -1;
        if let Err(e) = self.algorithm.start() {
            self.error = e;
            return Err(e);
        }
        Ok(())
    }

    /// `ZIP_SOURCE_CLOSE`.
    pub(crate) fn close(&mut self) -> Result<()> {
        if let Err(e) = self.algorithm.end() {
            self.error = e;
            return Err(e);
        }
        Ok(())
    }

    /// `ZIP_SOURCE_STAT`, on the lower source's stat: the data is stored
    /// now, of the size decompressed once the stream ended.
    pub(crate) fn stat(&self, st: &mut Stat<'_>) {
        st.comp_method = cm::STORE;
        st.valid |= stat::COMP_METHOD;
        st.valid &= !stat::COMP_SIZE;
        if self.end_of_stream {
            st.size = self.size;
            st.valid |= stat::SIZE;
        }
    }

    /// `ZIP_SOURCE_READ`: port of `compress_read`, reading the compressed
    /// data with `lower`.
    pub(crate) fn read(
        &mut self,
        data: &mut [u8],
        lower: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
    ) -> Result<usize> {
        if self.error.is_set() {
            return Err(self.error);
        }
        if data.is_empty() || self.end_of_stream {
            return Ok(0);
        }

        let len = data.len();
        let mut out_offset = 0;
        let mut end = false;
        while !end && out_offset < len {
            let (ret, out_len) = self
                .algorithm
                .process(&self.buffer[..], &mut data[out_offset..]);
            if !matches!(ret, CompressionStatus::Error(_)) {
                out_offset += out_len;
            }

            match ret {
                CompressionStatus::End => {
                    self.end_of_stream = true;
                    if !self.end_of_input {
                        let n = match lower(&mut self.buffer[..1]) {
                            Ok(0) => {
                                self.end_of_input = true;
                                usize::from(self.algorithm.end_of_input())
                            }
                            Ok(n) => n,
                            Err(e) => {
                                self.error = e;
                                break;
                            }
                        };
                        if n > 0 && self.check_consistency {
                            // garbage after stream, or compression ended
                            // before all data read
                            self.error = Error::incons(Detail::CompressedDataTrailingGarbage);
                            break;
                        }
                    }

                    if self.first_read < 0 {
                        // we got end of processed stream before reading any
                        // input data
                        self.error = Error::new(ErrorCode::Internal, 0);
                        break;
                    }
                    end = true;
                }
                CompressionStatus::Ok => {}
                CompressionStatus::NeedData => {
                    if self.end_of_input {
                        // TODO in libzip: error: stream not ended, but no
                        // more input
                        end = true;
                        continue;
                    }

                    match lower(&mut self.buffer[..]) {
                        Err(e) => {
                            self.error = e;
                            end = true;
                        }
                        Ok(0) => {
                            self.end_of_input = true;
                            self.algorithm.end_of_input();
                            if self.first_read < 0 {
                                self.first_read = 0;
                            }
                        }
                        Ok(n) => {
                            if self.first_read < 0 {
                                self.first_read = n as i64;
                            }
                            if let Err(e) = self.algorithm.input(n) {
                                self.error = e;
                            }
                        }
                    }
                }
                CompressionStatus::Error(e) => {
                    // error set by algorithm
                    self.error = if e.is_set() {
                        e
                    } else {
                        Error::new(ErrorCode::Internal, 0)
                    };
                    end = true;
                }
            }
        }

        if out_offset > 0 {
            self.size += out_offset as u64;
            return Ok(out_offset);
        }

        if self.error.is_set() {
            Err(self.error)
        } else {
            Ok(0)
        }
    }
}

/// `struct context`, for compressing.
pub(crate) struct Compress {
    pub(crate) error: Error,
    end_of_input: bool,
    end_of_stream: bool,
    /// whether the data may be stored instead, for `ZIP_CM_DEFAULT`
    can_store: bool,
    /// only valid if end_of_stream is true
    is_stored: bool,
    method: i32,
    size: u64,
    first_read: i64,
    buffer: Box<[u8; BUFSIZE]>,
    algorithm: DeflateCompress,
}

impl Compress {
    /// Port of `compression_source_new` and `context_new` for compressing
    /// with `method` at `compression_flags`: fails with
    /// `ZIP_ER_COMPNOTSUPP` if `method` has no algorithm.
    pub(crate) fn new(method: i32, compression_flags: u32) -> Result<Compress> {
        if cm_actual(method) != cm::DEFLATE {
            return Err(Error::new(ErrorCode::CompNotSupp, 0));
        }
        Ok(Compress {
            error: Error::OK,
            end_of_input: false,
            end_of_stream: false,
            can_store: method == CM_DEFAULT,
            is_stored: false,
            method,
            size: 0,
            first_read: -1,
            buffer: Box::new([0; BUFSIZE]),
            algorithm: DeflateCompress::new(compression_flags),
        })
    }

    /// `ZIP_SOURCE_OPEN`, once the lower source's stat and attributes were
    /// read.
    pub(crate) fn open(&mut self) -> Result<()> {
        self.size = 0;
        self.end_of_input = false;
        self.end_of_stream = false;
        self.is_stored = false;
        self.first_read = -1;
        if let Err(e) = self.algorithm.start() {
            self.error = e;
            return Err(e);
        }
        Ok(())
    }

    /// `ZIP_SOURCE_CLOSE`.
    pub(crate) fn close(&mut self) -> Result<()> {
        if let Err(e) = self.algorithm.end() {
            self.error = e;
            return Err(e);
        }
        Ok(())
    }

    /// `ZIP_SOURCE_STAT`, on the lower source's stat: the method and the
    /// compressed size once the stream ended, stored if it was.
    pub(crate) fn stat(&self, st: &mut Stat<'_>) {
        if self.end_of_stream {
            st.comp_method = if self.is_stored {
                cm::STORE
            } else {
                cm_actual(self.method)
            };
            st.comp_size = self.size;
            st.valid |= stat::COMP_SIZE | stat::COMP_METHOD;
        } else {
            st.valid &= !(stat::COMP_SIZE | stat::COMP_METHOD);
        }
    }

    /// `ZIP_SOURCE_GET_FILE_ATTRIBUTES`: the general purpose bits of the
    /// level, none if the data was stored.
    pub(crate) fn file_attributes(&self) -> FileAttributes {
        compression_attributes(if self.is_stored {
            0
        } else {
            self.algorithm.general_purpose_bit_flags()
        })
    }

    /// `ZIP_SOURCE_READ`: port of `compress_read`, reading the data to
    /// compress with `lower`. With `ZIP_CM_DEFAULT`, data read in one piece
    /// is stored if it does not compress in the same call.
    pub(crate) fn read(
        &mut self,
        data: &mut [u8],
        lower: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
    ) -> Result<usize> {
        if self.error.is_set() {
            return Err(self.error);
        }
        if data.is_empty() || self.end_of_stream {
            return Ok(0);
        }

        let len = data.len();
        let mut out_offset = 0;
        let mut end = false;
        while !end && out_offset < len {
            let (ret, out_len) = self
                .algorithm
                .process(&self.buffer[..], &mut data[out_offset..]);
            if !matches!(ret, CompressionStatus::Error(_)) {
                out_offset += out_len;
            }

            match ret {
                CompressionStatus::End => {
                    self.end_of_stream = true;
                    if !self.end_of_input {
                        match lower(&mut self.buffer[..1]) {
                            Ok(0) => {
                                self.end_of_input = true;
                                self.algorithm.end_of_input();
                            }
                            Ok(_) => {}
                            Err(e) => {
                                self.error = e;
                                break;
                            }
                        }
                    }

                    if self.first_read < 0 {
                        // we got end of processed stream before reading any
                        // input data
                        self.error = Error::new(ErrorCode::Internal, 0);
                        break;
                    }
                    if self.can_store && self.first_read as u64 <= out_offset as u64 {
                        self.is_stored = true;
                        self.size = self.first_read as u64;
                        let n = self.size as usize;
                        data[..n].copy_from_slice(&self.buffer[..n]);
                        return Ok(n);
                    }
                    end = true;
                }
                CompressionStatus::Ok => {}
                CompressionStatus::NeedData => {
                    if self.end_of_input {
                        // TODO in libzip: error: stream not ended, but no
                        // more input
                        end = true;
                        continue;
                    }

                    match lower(&mut self.buffer[..]) {
                        Err(e) => {
                            self.error = e;
                            end = true;
                        }
                        Ok(0) => {
                            self.end_of_input = true;
                            self.algorithm.end_of_input();
                            if self.first_read < 0 {
                                self.first_read = 0;
                            }
                        }
                        Ok(n) => {
                            if self.first_read >= 0 {
                                // we overwrote a previously filled
                                // ctx->buffer
                                self.can_store = false;
                            } else {
                                self.first_read = n as i64;
                            }
                            if let Err(e) = self.algorithm.input(n) {
                                self.error = e;
                            }
                        }
                    }
                }
                CompressionStatus::Error(e) => {
                    // error set by algorithm
                    self.error = if e.is_set() {
                        e
                    } else {
                        Error::new(ErrorCode::Internal, 0)
                    };
                    end = true;
                }
            }
        }

        if out_offset > 0 {
            self.can_store = false;
            self.size += out_offset as u64;
            return Ok(out_offset);
        }

        if self.error.is_set() {
            Err(self.error)
        } else {
            Ok(0)
        }
    }
}
