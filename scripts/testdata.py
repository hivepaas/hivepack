#!/usr/bin/env python3
"""Fetch and generate the test data that is too big to keep in the repository.

testdata/manifest.json lists every set:
- Sets with a "path" are committed under testdata/.
- Sets with "fetch" are downloaded, checked against their SHA-256 and unpacked
  into <cache>/<name>.
- Sets with "generate" are made in <cache>/<name> by zstd's own tools, or
  by the oracles in tools/, built from the pinned zstd, zlib, bzip2, lz4,
  XZ Utils, libzip and nettle releases, or with Go from the modules their
  go.sum pins.

The cache is target/testdata, or $HIVEPACK_TESTDATA when set.

    python3 scripts/testdata.py fetch [--group core|generated|fuzz|bench|all ...]
    python3 scripts/testdata.py list

Only the standard library is used, so any Python 3.9 or newer runs it.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "testdata" / "manifest.json"
GROUPS = ["core", "generated", "fuzz", "bench"]


def cache_dir() -> Path:
    return Path(os.environ.get("HIVEPACK_TESTDATA", ROOT / "target" / "testdata"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, want: str, downloads: Path) -> Path:
    """The file at url, kept in downloads, once its SHA-256 is want."""
    target = downloads / f"{want[:16]}-{PurePosixPath(url).name}"
    if target.exists() and sha256(target) == want:
        return target
    downloads.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(target.suffix + ".part")
    for attempt in range(4):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "hivepack-testdata"})
            with urllib.request.urlopen(request, timeout=120) as response, partial.open("wb") as out:
                shutil.copyfileobj(response, out)
            break
        except OSError as error:
            if attempt == 3:
                raise SystemExit(f"download failed: {url}: {error}")
            time.sleep(2 ** attempt)
    got = sha256(partial)
    if got != want:
        partial.unlink()
        raise SystemExit(f"checksum mismatch for {url}: want {want}, got {got}")
    partial.replace(target)
    return target


def safe_member(name: str) -> PurePosixPath:
    """A member name as a relative path, refusing anything that would land
    outside the set's folder."""
    path = PurePosixPath(name)
    parts = [p for p in path.parts if p not in ("", ".")]
    if path.is_absolute() or ".." in parts or (parts and ":" in parts[0]):
        raise SystemExit(f"refusing archive member {name!r}")
    return PurePosixPath(*parts) if parts else PurePosixPath()


def unpack(archive: Path, kind: str, into: Path) -> None:
    if kind == "zip":
        with zipfile.ZipFile(archive) as z:
            for info in z.infolist():
                rel = safe_member(info.filename)
                if info.is_dir() or not rel.parts:
                    continue
                dest = into.joinpath(*rel.parts)
                dest.parent.mkdir(parents=True, exist_ok=True)
                with z.open(info) as src, dest.open("wb") as out:
                    shutil.copyfileobj(src, out)
    elif kind == "tar.gz":
        with tarfile.open(archive, "r:gz") as t:
            for member in t.getmembers():
                rel = safe_member(member.name)
                if not rel.parts:
                    continue
                dest = into.joinpath(*rel.parts)
                if member.isdir():
                    dest.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    src = t.extractfile(member)
                    assert src is not None
                    with src, dest.open("wb") as out:
                        shutil.copyfileobj(src, out)
                    dest.chmod(0o755 if member.mode & 0o111 else 0o644)
                # Links and devices are not needed and are skipped.
    elif kind == "none":
        into.mkdir(parents=True, exist_ok=True)
        name = archive.name.split("-", 1)[1]
        shutil.copyfile(archive, into / name)
    else:
        raise SystemExit(f"unknown unpack kind {kind!r}")


def stamp_of(entry: dict) -> str:
    """What a finished set was made from: its manifest entry, and the
    repository sources a generated set is built from."""
    stamp = {"spec": entry.get("fetch") or entry.get("generate")}
    for source in entry.get("generate", {}).get("sources", []):
        stamp[source] = sha256(ROOT / source)
    return json.dumps(stamp, sort_keys=True)


def is_current(folder: Path, stamp: str) -> bool:
    marker = folder / ".complete"
    return marker.exists() and marker.read_text() == stamp


def mark_current(folder: Path, stamp: str) -> None:
    (folder / ".complete").write_text(stamp)


def fetch_set(entry: dict, cache: Path) -> None:
    folder = cache / entry["name"]
    stamp = stamp_of(entry)
    if is_current(folder, stamp):
        print(f"  {entry['name']}: up to date")
        return
    if folder.exists():
        shutil.rmtree(folder)
    staging = cache / f".{entry['name']}.partial"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    for file in entry["fetch"]["files"]:
        archive = download(file["url"], file["sha256"], cache / "downloads")
        unpack(archive, file.get("unpack", "none"), staging)
    mark_current(staging, stamp)
    staging.replace(folder)
    print(f"  {entry['name']}: fetched")


def build_tool(source: Path, tool: str) -> Path:
    """zstd's test tool built from the release sources, with zstd's own
    Makefile and the system C compiler."""
    tests = next(source.glob("zstd-*/tests"))
    binary = tests / tool
    if not binary.exists():
        print(f"  building {tool} from {tests.parent.name}")
        jobs = str(os.cpu_count() or 2)
        subprocess.run(["make", "-C", str(tests), "-j", jobs, tool], check=True,
                       stdout=subprocess.DEVNULL)
    return binary


def libzip_sources(lib: Path) -> list:
    """The library's C files, as lib/CMakeLists.txt lists them in ZIP_SOURCES,
    with the Unix ones it adds; zip_err_str.c is generated apart."""
    text = (lib / "CMakeLists.txt").read_text()
    listed = text.split("set(ZIP_SOURCES", 1)[1].split(")", 1)[0].split()
    names = [n for n in listed if n.endswith(".c") and not n.startswith("$")]
    return names + ["zip_source_file_stdio_named.c", "zip_random_unix.c"]


# libbzip2: the library's files of bzip2's Makefile (OBJS), without the
# bzip2 program and its tools.
BZIP2_SOURCES = [
    "blocksort.c", "huffman.c", "crctable.c", "randtable.c", "compress.c", "decompress.c",
    "bzlib.c",
]


# liblz4: the library's files (lib/), as lz4's lib/Makefile builds them,
# with xxHash's names prefixed as there.
LZ4_SOURCES = ["lz4.c", "lz4frame.c", "lz4hc.c", "xxhash.c"]
LZ4_FLAGS = ["-DXXH_NAMESPACE=LZ4_"]


# liblzma: the folders of its C files, without the multithreaded coders, the
# hardware queries (which need tuklib), the small CRCs of HAVE_SMALL, and
# the programs that write tables. delta/ and simple/ are left out with
# their filters (see tools/xz-oracle/config.h); only their headers, which
# the filter tables include, are on the include path.
LIBLZMA_DIRS = ["common", "check", "lz", "lzma", "rangecoder"]
LIBLZMA_LEFT_OUT = ["stream_encoder_mt", "stream_decoder_mt", "outqueue", "hardware_",
                    "crc32_small", "crc64_small", "tablegen", "crc_clmul_consts_gen"]


# nettle's AES (encryption only), SHA-1, HMAC-SHA1 and PBKDF2-HMAC-SHA1, in
# C: what the oracles call, without the assembly versions or the fat
# builds that choose between them.
NETTLE_SOURCES = [
    "aes-set-encrypt-key.c", "aes128-set-encrypt-key.c", "aes192-set-encrypt-key.c",
    "aes256-set-encrypt-key.c", "aes-set-key-internal.c", "aes-encrypt-internal.c",
    "aes-encrypt-table.c", "aes128-encrypt.c", "aes192-encrypt.c", "aes256-encrypt.c",
    "sha1.c", "sha1-compress.c", "sha1-meta.c", "hmac.c", "hmac-sha1.c", "pbkdf2.c",
    "pbkdf2-hmac-sha1.c", "memxor.c", "write-be32.c",
]


# What nettle's C files need of the config.h its configure writes: alloca,
# which every system the oracles are built on has. Without it, nettle's
# temporary arrays are local to the block that declares them, and
# hmac_set_key keeps a pointer to the digest of a key longer than a block
# past its block: gcc happens to leave it there, clang does not.
NETTLE_FLAGS = ["-DHAVE_ALLOCA=1", "-include", "alloca.h"]


def nettle_headers(nettle: Path, folder: Path) -> Path:
    """A folder with nettle's headers in nettle/, as an installed nettle has
    them, for `#include <nettle/aes.h>`. Without config.h (HAVE_CONFIG_H
    unset, NETTLE_FLAGS in its place), nettle's C files assume a
    little-endian machine, which the oracles are built on."""
    include = folder / "include"
    (include / "nettle").mkdir(parents=True)
    for header in nettle.glob("*.h"):
        shutil.copy(header, include / "nettle" / header.name)
    return include


# What lib/CMakeLists.txt adds to ZIP_SOURCES with HAVE_CRYPTO and
# HAVE_GNUTLS, and with HAVE_LIBBZ2.
LIBZIP_CRYPTO_SOURCES = [
    "zip_crypto_gnutls.c", "zip_winzip_aes.c", "zip_source_winzip_aes_decode.c",
    "zip_source_winzip_aes_encode.c",
]
LIBZIP_BZIP2_SOURCES = ["zip_algorithm_bzip2.c"]


def zip_err_str(lib: Path) -> str:
    """zip_err_str.c, as libzip's cmake/GenerateZipErrorStrings.cmake writes
    it from the comments in zip.h and zipint.h."""
    pattern = r"#define ZIP_ER_{}([A-Z0-9_]+) ([0-9]+)[ \t]+/([-*0-9a-zA-Z, ']*)/"
    errors = re.findall(pattern.format(""), (lib / "zip.h").read_text())
    details = re.findall(pattern.format("DETAIL_"), (lib / "zipint.h").read_text())
    out = ['#include "zipint.h"', "#define L ZIP_ET_LIBZIP", "#define N ZIP_ET_NONE",
           "#define S ZIP_ET_SYS", "#define Z ZIP_ET_ZLIB", "#define E ZIP_DETAIL_ET_ENTRY",
           "#define G ZIP_DETAIL_ET_GLOBAL", "const struct _zip_err_info _zip_err_str[] = {"]
    for _, _, text in errors:
        kind, description = re.search(r"([LNSZ]+) ([-0-9a-zA-Z, ']*)", text).groups()
        out.append(f'    {{ {kind}, "{description.strip()}" }},')
    out += ["};", "const int _zip_err_str_count = sizeof(_zip_err_str)/sizeof(_zip_err_str[0]);",
            "const struct _zip_err_info _zip_err_details[] = {"]
    for _, _, text in details:
        kind, description = re.search(r"([EG]+) ([-0-9a-zA-Z, ']*)", text).groups()
        out.append(f'    {{ {kind}, "{description.strip()}" }},')
    out += ["};", "const int _zip_err_details_count = sizeof(_zip_err_details)/sizeof(_zip_err_details[0]);"]
    return "\n".join(out) + "\n"


def build_oracle(source: Path, sources: list, included: list, folder: Path, extra: list) -> None:
    """An oracle program, compiled with the library's own sources.

    tools/zstd-oracle is built with libzstd's (without the assembly loop,
    which the port does not have either, and with its threads); the
    `included` files are left out, as the oracle includes them itself to
    reach their static functions.
    tools/zlib-oracle is built with zlib's, without the gzip file functions
    (gz*.c), which it does not use, and with contrib/infback9 for
    Deflate64. tools/bzip2-oracle is built with libbzip2's BZIP2_SOURCES,
    tools/lz4-oracle with liblz4's LZ4_SOURCES, and tools/xz-oracle with
    liblzma's, from LIBLZMA_DIRS, and its own config.h.
    tools/nettle-oracle is built with nettle's NETTLE_SOURCES.
    tools/zip-oracle is built with libzip's, its crypto backend for
    GnuTLS and its bzip2 algorithm among them, its own config.h and
    zipconf.h in place of those libzip's CMake build writes, the part of
    GnuTLS that backend uses in gnutls/, and zlib's, nettle's and
    libbzip2's (the `extra` sets)."""
    files = [str(ROOT / s) for s in sources if s.endswith(".c")]
    compiler = os.environ.get("CC", "cc")
    libzip = next(source.glob("libzip-*"), None)
    if libzip is not None:
        lib = libzip / "lib"
        zlib = next(extra[0].glob("zlib-*"))
        nettle = next(extra[1].glob("nettle-*"))
        bzip2 = next(extra[2].glob("bzip2-*"))
        generated = folder / "generated"
        generated.mkdir()
        (generated / "zip_err_str.c").write_text(zip_err_str(lib))
        files += [str(lib / name) for name in
                  libzip_sources(lib) + LIBZIP_CRYPTO_SOURCES + LIBZIP_BZIP2_SOURCES]
        files += [str(generated / "zip_err_str.c")]
        files += sorted(str(f) for f in zlib.glob("*.c") if not f.name.startswith("gz"))
        files += [str(nettle / name) for name in NETTLE_SOURCES]
        files += [str(bzip2 / name) for name in BZIP2_SOURCES]
        include = nettle_headers(nettle, folder)
        config = ROOT / Path(sources[0]).parent
        subprocess.run([compiler, "-O2", "-w", *NETTLE_FLAGS, f"-I{config}", f"-I{lib}", f"-I{zlib}",
                        f"-I{include}", f"-I{nettle}", f"-I{bzip2}", *files, "-o", str(folder / "oracle")],
                       check=True)
        return
    zlib = next(source.glob("zlib-*"), None)
    if zlib is not None:
        infback9 = zlib / "contrib" / "infback9"
        files += sorted(str(f) for f in zlib.glob("*.c") if not f.name.startswith("gz"))
        files += [str(infback9 / "infback9.c"), str(infback9 / "inftree9.c")]
        subprocess.run([compiler, "-O2", f"-I{zlib}", f"-I{infback9}", *files,
                        "-o", str(folder / "oracle")], check=True)
        return
    xz = next(source.glob("xz-*/src/liblzma"), None)
    if xz is not None:
        dirs = [xz / d for d in LIBLZMA_DIRS]
        files += sorted(str(f) for d in dirs for f in d.glob("*.c")
                        if not any(part in f.name for part in LIBLZMA_LEFT_OUT))
        config = ROOT / Path(sources[0]).parent
        headers = [xz / "api", *dirs, xz / "delta", xz / "simple", xz.parent / "common"]
        includes = [f"-I{d}" for d in [config, *headers]]
        subprocess.run([compiler, "-O2", "-w", "-DHAVE_CONFIG_H", *includes, *files,
                        "-o", str(folder / "oracle")], check=True)
        return
    bzip2 = next(source.glob("bzip2-*"), None)
    if bzip2 is not None:
        files += [str(bzip2 / name) for name in BZIP2_SOURCES]
        subprocess.run([compiler, "-O2", "-D_FILE_OFFSET_BITS=64", f"-I{bzip2}", *files,
                        "-o", str(folder / "oracle")], check=True)
        return
    lz4 = next(source.glob("lz4-*/lib"), None)
    if lz4 is not None:
        files += [str(lz4 / name) for name in LZ4_SOURCES]
        subprocess.run([compiler, "-O2", *LZ4_FLAGS, f"-I{lz4}", *files, "-o", str(folder / "oracle")],
                       check=True)
        return
    nettle = next(source.glob("nettle-*"), None)
    if nettle is not None:
        include = nettle_headers(nettle, folder)
        files += [str(nettle / name) for name in NETTLE_SOURCES]
        subprocess.run([compiler, "-O2", *NETTLE_FLAGS, f"-I{include}", f"-I{nettle}", *files,
                        "-o", str(folder / "oracle")], check=True)
        return
    lib = next(source.glob("zstd-*/lib"))
    for part in ("common", "compress", "decompress"):
        files += sorted(str(f) for f in (lib / part).glob("*.c")
                        if f"{part}/{f.name}" not in included)
    subprocess.run([compiler, "-O2", "-DZSTD_DISABLE_ASM", "-DZSTD_MULTITHREAD", "-pthread",
                    f"-I{lib}", f"-I{lib / 'common'}", *files, "-o", str(folder / "oracle")],
                   check=True)


def build_go(sources: list, folder: Path) -> None:
    """An oracle written in Go, built by the go command from its module in
    tools/. go.sum pins the modules it downloads, which the go command also
    checks against Go's checksum database; -mod=readonly keeps it from
    changing go.mod. An installed Go older than the one go.mod asks for
    downloads that one (GOTOOLCHAIN=auto, the default)."""
    go = shutil.which("go")
    if go is None:
        sys.exit("building the Go oracles needs Go: https://go.dev/dl/")
    module = ROOT / Path(sources[0]).parent
    subprocess.run([go, "build", "-trimpath", "-mod=readonly", "-o", str(folder / "oracle"), "."],
                   cwd=module, check=True, env={**os.environ, "CGO_ENABLED": "0"})


def generate_set(entry: dict, cache: Path, sets: dict) -> None:
    folder = cache / entry["name"]
    generate = entry["generate"]
    stamp = stamp_of(entry)
    if is_current(folder, stamp):
        print(f"  {entry['name']}: up to date")
        return
    if generate["tool"] == "go":
        if folder.exists():
            shutil.rmtree(folder)
        folder.mkdir(parents=True)
        build_go(generate["sources"], folder)
        mark_current(folder, stamp)
        print(f"  {entry['name']}: generated")
        return
    origin = sets[generate["from"]]
    fetch_set(origin, cache)
    extra = [sets[name] for name in generate.get("with", [])]
    for entry_with in extra:
        fetch_set(entry_with, cache)
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir(parents=True)
    if generate["tool"] == "oracle":
        build_oracle(cache / origin["name"], generate["sources"], generate.get("included", []), folder,
                     [cache / e["name"] for e in extra])
    else:
        binary = build_tool(cache / origin["name"], generate["tool"])
        # Each frame goes to z<number>.zst with its original at z<number>.
        subprocess.run([str(binary), f"-p{folder}", f"-o{folder}", *generate["args"]], check=True,
                       stdout=subprocess.DEVNULL)
    mark_current(folder, stamp)
    print(f"  {entry['name']}: generated")


def load_sets() -> dict:
    manifest = json.loads(MANIFEST.read_text())
    return {entry["name"]: entry for entry in manifest["sets"]}


def group_of(entry: dict):
    for key in ("fetch", "generate"):
        if key in entry:
            return entry[key]["group"]
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    fetch = sub.add_parser("fetch", help="download and generate sets")
    fetch.add_argument("--group", action="append", choices=GROUPS + ["all"],
                       help="sets to get (default: core); repeat for several")
    sub.add_parser("list", help="show every set and where it lives")
    args = parser.parse_args()

    sets = load_sets()
    cache = cache_dir()
    if args.command == "list":
        for entry in sets.values():
            group = group_of(entry)
            where = f"testdata/{entry['path']}" if group is None else f"{cache / entry['name']} ({group})"
            print(f"{entry['name']:36} {entry['kind']:12} {where}")
        return

    groups = set(args.group or ["core"])
    if "all" in groups:
        groups = set(GROUPS)
    for entry in sets.values():
        group = group_of(entry)
        if group not in groups:
            continue
        if "fetch" in entry:
            fetch_set(entry, cache)
        else:
            generate_set(entry, cache, sets)


if __name__ == "__main__":
    sys.exit(main())
