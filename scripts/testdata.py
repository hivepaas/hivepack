#!/usr/bin/env python3
"""Fetch and generate the test data that is too big to keep in the repository.

testdata/manifest.json lists every set:
- Sets with a "path" are committed under testdata/.
- Sets with "fetch" are downloaded, checked against their SHA-256 and unpacked
  into <cache>/<name>.
- Sets with "generate" are made in <cache>/<name> by zstd's own tools, built
  from the pinned zstd release.

The cache is target/testdata, or $HIVEPACK_TESTDATA when set.

    python3 scripts/testdata.py fetch [--group core|generated|fuzz|bench|all ...]
    python3 scripts/testdata.py list

Only the standard library is used, so any Python 3.9 or newer runs it.
"""

import argparse
import hashlib
import json
import os
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


def build_oracle(source: Path, sources: list, included: list, folder: Path) -> None:
    """tools/zstd-oracle, compiled with libzstd's own sources (without the
    assembly loop, which the port does not have either). The `included`
    files are left out: the oracle includes them itself, to reach their
    static functions."""
    lib = next(source.glob("zstd-*/lib"))
    files = [str(ROOT / s) for s in sources]
    for part in ("common", "compress", "decompress"):
        files += sorted(str(f) for f in (lib / part).glob("*.c")
                        if f"{part}/{f.name}" not in included)
    compiler = os.environ.get("CC", "cc")
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
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir(parents=True)
    if generate["tool"] == "oracle":
        build_oracle(cache / origin["name"], generate["sources"], generate.get("included", []), folder)
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
