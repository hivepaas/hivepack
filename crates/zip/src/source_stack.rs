//! The sources libzip stacks to read an entry, and the rules every
//! `zip_source_t` follows around its callback: port of the reading parts
//! of `zip_source_read.c`, `zip_source_open.c`, `zip_source_close.c`,
//! `zip_source_at_eof.c`, `zip_source_stat.c` and `zip_source_layered.c`.
//!
//! Differs from libzip: the stack is a struct, not a chain of callbacks.
//! It is always a window on the archive (or on an empty buffer), then the
//! decompressing layer if the data is compressed, then the CRC layer if
//! the CRC is to be checked, and each layer keeps the state libzip keeps
//! in its `zip_source_t`.

use crate::error::{Error, Result};
use crate::source::ReadAt;
use crate::source_compress::Decompress;
use crate::source_crc::Crc;
use crate::source_window::{Lower, UpperWindow, Window};
use crate::zip::Stat;

/// A layer: its callback's context, and what `zip_source_t` keeps.
pub(crate) struct Layer<T> {
    pub(crate) ctx: T,
    error: Error,
    /// EOF reached
    eof: bool,
    /// a previous ZIP_SOURCE_READ reported an error
    had_read_error: bool,
    /// byte read to determine EOF for sources that don't support
    /// ZIP_SOURCE_AT_EOF
    next_byte: Option<u8>,
}

impl<T> Layer<T> {
    pub(crate) fn new(ctx: T) -> Layer<T> {
        Layer {
            ctx,
            error: Error::OK,
            eof: false,
            had_read_error: false,
            next_byte: None,
        }
    }

    /// What `zip_source_open` resets once the callback opened.
    fn opened(&mut self) {
        self.eof = false;
        self.had_read_error = false;
        self.error = Error::OK;
    }

    /// Reads up to `data.len()` bytes with the callback `call`, until the
    /// callback returns none: port of `zip_source_read`. After an error,
    /// every read fails with it, and the bytes read before it in the same
    /// call are returned first.
    fn read(
        &mut self,
        data: &mut [u8],
        call: &mut dyn FnMut(&mut T, &mut [u8]) -> Result<usize>,
    ) -> Result<usize> {
        if self.had_read_error {
            return Err(self.error);
        }
        if self.eof || data.is_empty() {
            return Ok(0);
        }

        let mut bytes_read = 0;
        if let Some(byte) = self.next_byte.take() {
            data[0] = byte;
            bytes_read = 1;
        }

        while bytes_read < data.len() {
            match call(&mut self.ctx, &mut data[bytes_read..]) {
                Err(e) => {
                    self.had_read_error = true;
                    self.error = e;
                    return if bytes_read == 0 {
                        Err(e)
                    } else {
                        Ok(bytes_read)
                    };
                }
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(n) => bytes_read += n,
            }
        }
        Ok(bytes_read)
    }
}

/// The sources reading one entry, from the bottom up.
pub(crate) struct Stack<'a, R: ?Sized> {
    pub(crate) lower: Lower<'a, R>,
    pub(crate) window: Layer<Window>,
    pub(crate) decompress: Option<Layer<Decompress>>,
    pub(crate) crc: Option<Layer<Crc>>,
    /// the window on the decompressed data, for part of an entry
    pub(crate) partial: Option<Layer<UpperWindow>>,
    /// the entry, for the window's errors
    pub(crate) index: u64,
}

fn read_window<R: ReadAt + ?Sized>(
    window: &mut Layer<Window>,
    lower: &mut Lower<'_, R>,
    data: &mut [u8],
) -> Result<usize> {
    window.read(data, &mut |ctx, buf| ctx.read(lower, buf))
}

/// `zip_source_stat` of the window: the lower source's, then the window's.
fn stat_window<R: ReadAt + ?Sized>(window: &Layer<Window>, lower: &Lower<'_, R>) -> Stat<'static> {
    let mut st = lower.stat();
    window.ctx.stat(&mut st);
    st
}

fn read_decompress<R: ReadAt + ?Sized>(
    decompress: &mut Layer<Decompress>,
    window: &mut Layer<Window>,
    lower: &mut Lower<'_, R>,
    data: &mut [u8],
) -> Result<usize> {
    decompress.read(data, &mut |ctx, buf| {
        ctx.read(buf, &mut |b| read_window(window, lower, b))
    })
}

/// The source under the CRC layer: the decompressing one, or the window.
fn read_below_crc<R: ReadAt + ?Sized>(
    decompress: &mut Option<Layer<Decompress>>,
    window: &mut Layer<Window>,
    lower: &mut Lower<'_, R>,
    data: &mut [u8],
) -> Result<usize> {
    match decompress {
        Some(decompress) => read_decompress(decompress, window, lower, data),
        None => read_window(window, lower, data),
    }
}

fn stat_below_crc<R: ReadAt + ?Sized>(
    decompress: &Option<Layer<Decompress>>,
    window: &Layer<Window>,
    lower: &Lower<'_, R>,
) -> Stat<'static> {
    let mut st = stat_window(window, lower);
    if let Some(decompress) = decompress {
        decompress.ctx.stat(&mut st);
    }
    st
}

/// Whether the source under the CRC layer is at its end: port of
/// `zip_source_at_eof`. The window knows; the decompressing source does
/// not, and cannot seek, so a byte is read and kept for the next read.
fn at_eof_below_crc<R: ReadAt + ?Sized>(
    decompress: &mut Option<Layer<Decompress>>,
    window: &mut Layer<Window>,
    lower: &mut Lower<'_, R>,
) -> Result<bool> {
    match decompress {
        None => {
            if !window.eof {
                match window.ctx.at_eof() {
                    Some(true) => window.eof = true,
                    Some(false) => {}
                    // A window on an entry's data always has an end.
                    None => {}
                }
            }
            Ok(window.eof)
        }
        Some(layer) => {
            if !layer.eof {
                let mut d = [0];
                let n = read_decompress(layer, window, lower, &mut d)?;
                if n > 0 {
                    layer.next_byte = Some(d[0]);
                }
            }
            Ok(layer.eof)
        }
    }
}

/// The source under the partial window: the CRC layer, the decompressing
/// one, or the window on the archive.
fn read_below_partial<R: ReadAt + ?Sized>(
    crc: &mut Option<Layer<Crc>>,
    decompress: &mut Option<Layer<Decompress>>,
    window: &mut Layer<Window>,
    lower: &mut Lower<'_, R>,
    data: &mut [u8],
) -> Result<usize> {
    match crc {
        Some(crc) => crc.read(data, &mut |ctx, buf| {
            let n = read_below_crc(decompress, window, lower, buf);
            ctx.read(buf, n, || stat_below_crc(decompress, window, lower))
        }),
        None => read_below_crc(decompress, window, lower, data),
    }
}

impl<R: ReadAt + ?Sized> Stack<'_, R> {
    /// The size the stack below the partial window gives in its stat, if
    /// it gives one.
    pub(crate) fn size_below_partial(&self) -> Option<u64> {
        let st = stat_below_crc(&self.decompress, &self.window, &self.lower);
        (st.valid & crate::zip::stat::SIZE != 0).then_some(st.size)
    }

    /// Opens the layers, the lowest first: port of `zip_source_open`.
    pub(crate) fn open(&mut self) -> Result<()> {
        if let Err(e) = self.window.ctx.open(&mut self.lower, self.index) {
            self.window.error = e;
            return Err(e);
        }
        self.window.opened();

        if let Some(decompress) = self.decompress.as_mut() {
            if let Err(e) = decompress.ctx.open() {
                decompress.error = e;
                return Err(e);
            }
            decompress.opened();
        }

        if let Some(crc) = self.crc.as_mut() {
            crc.ctx.open();
            crc.opened();
        }

        let Stack {
            lower,
            window,
            decompress,
            crc,
            partial,
            ..
        } = self;
        if let Some(partial) = partial {
            if let Err(e) = partial
                .ctx
                .open(&mut |b| read_below_partial(crc, decompress, window, lower, b))
            {
                partial.error = e;
                return Err(e);
            }
            partial.opened();
        }
        Ok(())
    }

    /// `zip_source_read` of the top layer.
    pub(crate) fn read(&mut self, data: &mut [u8]) -> Result<usize> {
        let Stack {
            lower,
            window,
            decompress,
            crc,
            partial,
            ..
        } = self;
        match partial {
            Some(partial) => partial.read(data, &mut |ctx, buf| {
                ctx.read(buf, &mut |b| {
                    read_below_partial(crc, decompress, window, lower, b)
                })
            }),
            None => read_below_partial(crc, decompress, window, lower, data),
        }
    }

    /// Closes the layers, the top first: port of `zip_source_close`. The
    /// first error is the one returned.
    pub(crate) fn close(&mut self) -> Result<()> {
        let Stack {
            lower,
            window,
            decompress,
            crc,
            ..
        } = self;
        let mut ret = Ok(());
        if let Some(crc) = crc {
            let at_eof = at_eof_below_crc(decompress, window, lower);
            if let Err(e) = crc
                .ctx
                .close(at_eof, || stat_below_crc(decompress, window, lower))
            {
                crc.error = e;
                ret = Err(e);
            }
        }
        if let Some(decompress) = decompress
            && let Err(e) = decompress.ctx.close()
        {
            decompress.error = e;
            if ret.is_ok() {
                ret = Err(e);
            }
        }
        ret
    }
}
