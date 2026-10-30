# Opening through layers

`hivepack-open` takes off the layers around what hivepack reads: `backup.tar.zst.age` is a tar archive, compressed with zstd, then encrypted with age, and opens as the tar archive. Each layer is found by its first bytes, as `file` and the tools themselves find them, not by the file's name, which is often wrong or missing; and each is read with hivepack's port of its library: `hivepack-age`, `hivepack-zstd`, `hivepack-xz` (xz, lzip and .lzma), `hivepack-deflate` (gzip) and `hivepack-bzip2`.

> **Status:** age, zstd, xz, lzip, .lzma, gzip and bzip2, stacked in any order up to a limit, under which a tar archive, a ZIP archive or plain data; each read as its tools read it, checked with files the reference libraries and age make, and fuzzed. A tar archive under them extracts with `hivepack-extract`. Next: packwing's prompts for passphrases and keys.

## Finding the layers

`detect` looks at the first 1,570 bytes of a stream (`HEAD_LEN`: a tar header block, or an armored age file's 1 KiB of white space and its first line), in this order:

| What | How it is told |
|---|---|
| age | `age-encryption.org/`, or `-----BEGIN AGE ENCRYPTED FILE-----` after at most 1 KiB of white space, as `age --decrypt` tells armor |
| zstd | the frame magic `28 B5 2F FD`, or a skippable frame's (`50`–`5F 2A 4D 18`), which zstd reads past |
| xz | `FD 37 7A 58 5A 00` |
| lzip | `LZIP` |
| gzip | `1F 8B` |
| bzip2 | `BZh` and a block size, `1` to `9` |
| ZIP | `PK 03 04`, `PK 05 06` (an empty archive), `PK 07 08` (a split archive's marker) |
| tar | `ustar` at 257 (USTAR and GNU), or else a checksum that adds up, signed or not, with a name: V7 has no magic |
| .lzma | no magic: by the file's name, `.lzma` at its end, once the layers around it are taken off with their extensions (`backup.tar.lzma.age`) |

Anything else is data: one file, compressed or encrypted (`notes.txt.zst`), or, with no layer at all, something hivepack does not read. A layer is taken off, and the stream under it looked at again, until a container or data is found, or `Limits::max_layers` (8) are taken off.

## Reading each layer

The decoders are given as `io::Read`, over each library's streaming call, through one adapter. A file reads as its tools read it:

- **Several streams one after the other**, as the tools write and read them: zstd frames, skippable ones among them; gzip members (`cat a.gz b.gz`, and `pigz`); bzip2 streams (`pbzip2` writes one per block); xz streams with their padding; lzip members.
- **After the last**: zeros after gzip and bzip2, which tar's blocking leaves when a whole tape image is compressed; and anything after lzip's, as its format allows and `lzip` and `xz` ignore. That is read to its end too, so that the layers around it are read to theirs. Anything else after a stream fails (`trailing data after the end of the stream`). `gzip` and `bzip2` warn about other data and go on; Python's `gzip` fails, as here.
- **Cut short**, a stream fails (`the stream is cut short`), as do damaged data, the library's own message given (`incorrect data check`).
- **What a library produced before it failed is read first**, and the error at the next read: liblzma, zlib and libbzip2 write what they decoded before an error in the call that returns it, which the adapter keeps, so that what is read does not depend on the size of the reads. libzstd returns an error without what that call decoded, so what is read before its errors can.

An error of a layer's data is an `io::Error` of kind `InvalidData` holding a `DecodeError`, which names the layer and gives the library's message. An error stays: every later read returns it.

## Reading again

`hivepack_extract::extract_tar` reads an archive twice, once to check it all and once to write it, and so opens the file twice, and packwing opens it once more to tell what it is. An `Opener` holds what opens the file (a function, called again each time), its name, the identities that decrypt age layers, and the limits, and each `open` reads the file from its start, through its layers.

The first time an age layer is decrypted, its file key is kept, checked by the header's MAC; each later open decrypts that layer with it (`FileKeyIdentity`, age's `NewInjectedFileKeyIdentity`), so that a passphrase is asked for once, however many times the file is opened, and scrypt runs once: a third of a second at the work factor age encrypts with (2^18), twice that for each step up. Keys for each age layer are kept apart, the outermost first, for age inside age.

A file can change between opens. A later open must find the same layers and container as the first; and an age layer's kept key that does not match its header's MAC means another file encrypted again: both fail with `Error::Changed`. What is under the layers is `hivepack-extract`'s to compare: `extract_tar` compares each header with the first reading's.

`LazyScryptIdentity`, from `cmd/age`, asks for a passphrase only when a layer turns out to be encrypted with one; a file encrypted to keys asks nothing. A file no identity matches fails with `hivepack_age::Error::NoMatch`, whose stanza types (`scrypt`, `X25519`, `ssh-ed25519`) tell what it needs, so that an application can ask for that and open it again.

## Checks at the end of a stream

A compressor checks its data at the end of its stream (gzip's and bzip2's CRC-32, xz's and zstd's checks, lzip's CRC-32), and age authenticates its last chunk; a tar reader stops at the archive's end, which comes before. `extract_tar` reads on to the end of the stream, in both readings, as GNU tar reads its compressor's output to the end: a stream that fails there fails the first reading, before anything is written. What follows the archive's end is limited to `Limits::max_total_size`, or 1 MiB if that is less, the largest record tar pads to.

## What is left to the caller

- **A ZIP archive under layers** (`archive.zip.age`) is read by random access, from its end: it must be written to a file first, then opened with `hivepack-zip`. A ZIP archive with no layer is opened as it is.
- **Data** under layers is one file, whose name is the file's without the layers' extensions; writing it is the application's.

## Bounded resources

The layers are limited (8 by default), and so is what each decoder may allocate: zstd's window to 128 MiB (`zstd_window_log_max`, 27, libzstd's own default; a larger one needs `zstd --long` or `--memory` to decompress too), and liblzma to 1 GiB (`xz_memlimit`; `xz -9` needs 65 MiB). gzip needs its 32 KiB window, and bzip2 at most 3.7 MB, as their libraries do. Each layer has a 64 KiB buffer. age's limits are its own ([age.md](age.md)): an application that opens files from strangers lowers the scrypt work factor it accepts (`LazyScryptIdentity::set_max_work_factor`; 2^22 by default, 4 GiB and about 5 seconds). What is under the layers, decompressed, is limited by what reads it: `hivepack-extract`'s limits.

## How it is shown

- **`tests/open.rs`**: tar archives compressed by the reference libraries (libzstd, liblzma, zlib, libbzip2; lzip members made with liblzma's raw LZMA1 encoder and lzip's header and trailer, as liblzma has no lzip encoder), each layer alone and four stacked; several streams one after the other, a skippable frame first and between, zeros and xz's padding after; other data after them; each cut short at three places; damaged data; reads of a byte, into nothing, and from an input that gives a byte at a time and is interrupted between; the limits on layers, zstd's window and liblzma's memory; an error that stays; a file that changes between opens; `.lzma` by its name; and a tar archive under two layers extracted through the opener. A gzip file whose stored data has a byte changed fails `extract_tar` before anything is written: only its CRC-32 tells.
- **`tests/age.rs`**: files age v1.3.2 encrypts, through `tools/age-oracle` ([age.md](age.md)): tar archives under zstd, gzip and xz, a tar archive alone and plain data, to a passphrase or an X25519 key, armored or not, and age inside zstd inside age. Each opens to what opening the plaintext gives, three times, with one prompt for each layer that needs a passphrase; one extracts with one prompt; a wrong passphrase, no matching key (the stanza types say `scrypt`), a prompt refused and a file encrypted again between opens fail with their reasons. Where the oracle is built the files are encrypted afresh; `testdata/oracle/open.txt` holds files age encrypted for everywhere else.
- **Unit tests** for `detect`: each magic and near misses, armor after white space and after too much, ZIP's three signatures, USTAR, GNU and V7 tar with signed and unsigned checksums, and `.lzma` by its name.
- **Fuzzing**: the `open` target opens any input three times with one opener, with the age key of the recorded files and small limits, reading it in pieces of different sizes: each must find the same layers and end the same way, the data the same, or after an error the start of the other's. Its first five minutes found the adapter dropping what liblzma had decoded before an error in the same call, so that what was read depended on the size of the reads; the adapter keeps it now, which `tests/open.rs` checks. The next eight minutes, 865,000 inputs, found nothing.

## Next

packwing's prompts for passphrases and keys, and its settings for key files; a ZIP archive under layers, written to a temporary file; data under layers, extracted as a file; and the layers' own progress (the compressed bytes read), for a progress bar that knows the file's size.
