#!/usr/bin/env python3
"""What Linux's udf file system reads of a mounted image: one line per
entry, sorted by path, as crates/udf/tests/linux.rs words the port's.

    answer.py <mount point>

Each line is tab-separated: the path from the root in hexadecimal; the type
(d, f, l, c, b, p, s); the permission bits in octal, setuid, setgid and
sticky included; owner; group; links; size; the modification, access and
change times in nanoseconds; for a symbolic link its target in hexadecimal,
for a device "<major>,<minor>", else "-"; for a regular file the SHA-256 of
its data, else "-".
"""

import hashlib
import os
import stat
import sys


def kind(mode: int) -> str:
    for test, letter in [(stat.S_ISDIR, "d"), (stat.S_ISREG, "f"), (stat.S_ISLNK, "l"),
                         (stat.S_ISCHR, "c"), (stat.S_ISBLK, "b"), (stat.S_ISFIFO, "p"),
                         (stat.S_ISSOCK, "s")]:
        if test(mode):
            return letter
    return "?"


def line(root: bytes, rel: bytes) -> str:
    path = os.path.join(root, rel) if rel else root
    st = os.lstat(path)
    k = kind(st.st_mode)
    extra = "-"
    digest = "-"
    if k == "l":
        extra = os.readlink(path).hex() or "-"
    elif k in "cb":
        extra = f"{os.major(st.st_rdev)},{os.minor(st.st_rdev)}"
    elif k == "f":
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        digest = h.hexdigest()
    return "\t".join([
        rel.hex() or ".", k, f"{stat.S_IMODE(st.st_mode):o}", str(st.st_uid), str(st.st_gid),
        str(st.st_nlink), str(st.st_size), str(st.st_mtime_ns), str(st.st_atime_ns),
        str(st.st_ctime_ns), extra, digest,
    ])


def main() -> None:
    root = os.fsencode(sys.argv[1])
    paths = [b""]
    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        rel = b"" if rel == b"." else rel
        for name in dirnames + filenames:
            paths.append(os.path.join(rel, name) if rel else name)
    for rel in sorted(paths):
        print(line(root, rel))


if __name__ == "__main__":
    main()
