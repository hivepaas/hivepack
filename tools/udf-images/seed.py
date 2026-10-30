#!/usr/bin/env python3
"""Seeds for the udf fuzz target: images as it reads them, their sectors by
number and length, without the zeros they end with, only those that hold a
descriptor and those of the first 64 KiB.

    seed.py <out> [<folder of crafted .udf images>]

Reads testdata/udf/*.udf.xz, from the repository, and the crafted images if
given (those crates/udf/tests/crafted.rs writes with write_crafted_images).
"""

import lzma
import pathlib
import re
import struct
import sys

# The tag identifiers of ECMA-167's parts 3 and 4.
IDS = set(range(0, 10)) | set(range(256, 267))


def block_size(name: str) -> int:
    m = re.search(r"-bs(\d+)", name)
    if m:
        return int(m.group(1))
    # mkudffs takes 512 for an image on a hard disk.
    return 512 if name.startswith("mkudffs-hd-") else 2048


def tagged(sector: bytes) -> bool:
    """A descriptor's tag somewhere in the sector, at a multiple of 4."""
    for o in range(0, len(sector) - 16, 4):
        t = sector[o:o + 16]
        if (int.from_bytes(t[0:2], "little") in IDS and t[2] in (2, 3)
                and t[4] == (sum(t[0:4]) + sum(t[5:16])) & 0xFF and any(t)):
            return True
    return False


def seed(out: pathlib.Path, name: str, data: bytes, bs: int) -> None:
    count = min(len(data) // bs, 1 << 16)
    rec = bytearray([{512: 0, 1024: 1, 2048: 2, 4096: 3}[bs]]) + count.to_bytes(3, "little")
    for s in range(count):
        sector = data[s * bs:(s + 1) * bs]
        if any(sector) and (s * bs < 65536 or tagged(sector)):
            body = sector.rstrip(b"\0")
            rec += struct.pack("<IH", s, len(body)) + body
    (out / name).write_bytes(bytes(rec))


def main() -> None:
    out = pathlib.Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    for p in sorted(pathlib.Path("testdata/udf").glob("*.udf.xz")):
        name = p.name[:-len(".udf.xz")]
        seed(out, name, lzma.decompress(p.read_bytes()), block_size(name))
    if len(sys.argv) > 2:
        for p in sorted(pathlib.Path(sys.argv[2]).glob("*.udf")):
            seed(out, "crafted-" + p.stem, p.read_bytes(), block_size(p.stem))


if __name__ == "__main__":
    main()
