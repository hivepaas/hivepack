//! The decompressing layer: port of `zip_source_compress.c`, the
//! decompressing half, with deflate its only algorithm for now.

use crate::algorithm_deflate::{CompressionStatus, DeflateDecompress};
use crate::error::{Detail, Error, ErrorCode, Result};
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
/// come with their crates.
pub(crate) fn get_compression_algorithm(method: u16) -> Option<DeflateDecompress> {
    (method == cm::DEFLATE).then(DeflateDecompress::new)
}

impl Decompress {
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
