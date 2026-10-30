# ZipDiff's ambiguous archives

`constructions.zip` holds the 5,927 archives that ZipDiff's `construction` program writes: ZIP files that parsers read differently, one folder for each type of ambiguity in "My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers" (Yufan You and others, USENIX Security 2025). They are the program's output, unchanged.

| Folder | Archives | What disagrees |
|---|---|---|
| `a1` to `a5` | 2, 4,609, 7, 9, 3 | what is said twice: the method and size of stored data in one header and not the other (`a1`); the sizes in the local header, the central directory, a data descriptor and Zip64 fields, every combination of zero or not (`a2`); the name in each header and in the Unicode path field, with its version and CRC-32, and the UTF-8 flag (`a3`); a trailing slash or backslash, and the DOS or Unix attributes of a directory (`a4`); the encryption flag (`a5`) |
| `b1` to `b4` | 1, 1,182, 20, 1 | names: one name twice (`b1`); every byte that is not a letter or digit, from DOS or Unix (`b2`); `a/b` against `/a/b`, `a//b`, `a\b`, `./a/b`, `../a/b`, `c/../a/b` and others, first or second (`b3`); `test.txt` and `test.TXT` (`b4`) |
| `c1` to `c5` | 7, 3, 8, 1, 74 | where things are: local headers no central header lists, records that stop a scan, local headers that run into each other, and where a data descriptor is (`c1`); which end of central directory record is taken when there are several (`c2`); entry counts against the central directory, and counts past 65,535 (`c3`); a central directory offset read with or without the data before the archive (`c4`); Zip64 records, found by their locator or by searching, and their counts and offsets (`c5`) |

They come from https://github.com/ouuan/ZipDiff at commit 7c427ed254bb3a5985d54870c12f97db78118e67 (Apache-2.0, see `LICENSE`), made once with its own `Cargo.lock`:

```sh
cd zip-diff
cargo build --release --locked --bin construction
target/release/construction        # writes ../constructions/<type>/<type>-<n>.zip
```

and packed, sorted by path, into one deflated archive, so that the repository holds one file and not six thousand. The tests read it with hivepack-zip.
