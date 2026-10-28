#!/usr/bin/env python3
"""Fetch and generate the test data that is too big to keep in the repository.

testdata/manifest.json lists every set:
- Sets with a "path" are committed under testdata/.
- Sets with "fetch" are downloaded, checked against their SHA-256 and unpacked
  into <cache>/<name>.
- Sets with "generate" are made in <cache>/<name> by zstd's own tools, or
  by the oracles in tools/, built from the pinned zstd and zlib releases.

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
    which the port does not have either); the `included` files are left
    out, as the oracle includes them itself to reach their static functions.
    tools/zlib-oracle is built with zlib's, without the gzip file functions
    (gz*.c), which it does not use, and with contrib/infback9 for
    Deflate64. tools/zip-oracle is built with libzip's, its own config.h and
    zipconf.h in place of those libzip's CMake build writes, and zlib's
    (the `extra` set)."""
    files = [str(ROOT / s) for s in sources if s.endswith(".c")]
    compiler = os.environ.get("CC", "cc")
    libzip = next(source.glob("libzip-*"), None)
    if libzip is not None:
        lib = libzip / "lib"
        zlib = next(extra[0].glob("zlib-*"))
        generated = folder / "generated"
        generated.mkdir()
        (generated / "zip_err_str.c").write_text(zip_err_str(lib))
        files += [str(lib / name) for name in libzip_sources(lib)] + [str(generated / "zip_err_str.c")]
        files += sorted(str(f) for f in zlib.glob("*.c") if not f.name.startswith("gz"))
        config = ROOT / Path(sources[0]).parent
        subprocess.run([compiler, "-O2", "-w", f"-I{config}", f"-I{lib}", f"-I{zlib}", *files,
                        "-o", str(folder / "oracle")], check=True)
        return
    zlib = next(source.glob("zlib-*"), None)
    if zlib is not None:
        infback9 = zlib / "contrib" / "infback9"
        files += sorted(str(f) for f in zlib.glob("*.c") if not f.name.startswith("gz"))
        files += [str(infback9 / "infback9.c"), str(infback9 / "inftree9.c")]
        subprocess.run([compiler, "-O2", f"-I{zlib}", f"-I{infback9}", *files,
                        "-o", str(folder / "oracle")], check=True)
        return
    lib = next(source.glob("zstd-*/lib"))
    for part in ("common", "compress", "decompress"):
        files += sorted(str(f) for f in (lib / part).glob("*.c")
                        if f"{part}/{f.name}" not in included)
    subprocess.run([compiler, "-O2", "-DZSTD_DISABLE_ASM", f"-I{lib}", f"-I{lib / 'common'}",
                    *files, "-o", str(folder / "oracle")], check=True)


def generate_set(entry: dict, cache: Path, sets: dict) -> None:
    folder = cache / entry["name"]
    generate = entry["generate"]
    stamp = stamp_of(entry)
    if is_current(folder, stamp):
        print(f"  {entry['name']}: up to date")
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
