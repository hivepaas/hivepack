//! Huffman coding constants: port of the parts of `common/huf.h` the port
//! needs so far.

/// `HUF_BLOCKSIZE_MAX`: the largest input of one Huffman-compressed block.
pub(crate) const HUF_BLOCKSIZE_MAX: usize = 128 * 1024;
/// `HUF_TABLELOG_MAX`: the largest table log at run time.
pub(crate) const HUF_TABLELOG_MAX: u32 = 12;
/// `HUF_TABLELOG_DEFAULT`
pub(crate) const HUF_TABLELOG_DEFAULT: u32 = 11;
/// `HUF_SYMBOLVALUE_MAX`
pub(crate) const HUF_SYMBOLVALUE_MAX: u32 = 255;
/// `HUF_TABLELOG_ABSOLUTEMAX`
pub(crate) const HUF_TABLELOG_ABSOLUTEMAX: u32 = 12;
