#!/bin/bash
# Makes the UDF test images of testdata/udf and what Linux reads of them.
#
# Runs as root in a Linux with the udf file system and loop devices, for
# example:
#
#   docker run --rm --privileged -v "$PWD":/repo -w /repo ubuntu:24.04 \
#       tools/udf-images/make.sh /repo/testdata/udf
#
# Each image is made with mkudffs (udftools) or genisoimage, filled through
# Linux's udf file system mounted read-write where it can write, and then
# mounted read-only for tools/udf-images/answer.py. <out>/<name>.udf.xz is
# the image, <out>/<name>.txt what Linux reads of it.

set -euo pipefail

out=${1:?the folder to write to}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"

if ! command -v mkudffs >/dev/null || ! command -v genisoimage >/dev/null; then
    apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq udftools genisoimage xz-utils python3 >/dev/null
fi

work=$(mktemp -d)
mnt=$work/mnt
mkdir -p "$mnt"
trap 'umount "$mnt" 2>/dev/null || true; rm -rf "$work"' EXIT

# Bytes of a pattern: <count> <seed>, written to stdout.
pattern() {
    python3 -c "import sys; n, s = int(sys.argv[1]), int(sys.argv[2]); sys.stdout.buffer.write(bytes((i * 7 + s) % 251 for i in range(n)))" "$1" "$2"
}

# What the images hold: every kind of entry the udf file system writes.
fill() {
    local d=$1
    mkdir -p "$d/dir/sub/deeper/deepest" "$d/many" "$d/sticky"
    : > "$d/empty"
    printf 'x' > "$d/one"
    pattern 100 1 > "$d/small"
    pattern 2048 2 > "$d/block"
    pattern 70000 3 > "$d/dir/medium"
    pattern 5000000 4 > "$d/dir/sub/large"
    pattern 333 5 > "$d/dir/sub/deeper/deepest/leaf"
    # A file with a hole in its middle.
    pattern 4096 6 > "$d/sparse"
    truncate -s 3000000 "$d/sparse"
    pattern 4096 7 >> "$d/sparse"
    for i in $(seq 1 300); do printf 'file %d\n' "$i" > "$d/many/entry-$i"; done
    printf 'é' > "$d/café"
    printf 'zh' > "$d/中文名"
    printf 'emoji' > "$d/😀 smile"
    printf 'long' > "$d/$(printf 'n%.0s' $(seq 1 250))"
    printf 'odd' > "$d/a:b*c?d \"e\" <f>|g\\h"
    printf 'dot' > "$d/.hidden"
    ln -s small "$d/link"
    ln -s ../one "$d/dir/up"
    ln -s /etc/passwd "$d/absolute"
    ln -s dir/sub "$d/to-dir"
    ln -s missing "$d/dangling"
    ln -s "./a//b/../c" "$d/odd-link"
    ln -s a-moderately-long-symbolic-link-target/with/several/components/to/encode "$d/long-link"
    ln "$d/small" "$d/hard"
    mkfifo "$d/fifo"
    mknod "$d/char" c 1 3
    mknod "$d/block-dev" b 7 0
    chmod 0644 "$d/small"; chmod 4755 "$d/one"; chmod 0000 "$d/block"; chmod 0750 "$d/dir"
    chmod 1777 "$d/sticky"; chmod 2711 "$d/dir/medium"
    chown 1000:1000 "$d/small"; chown 0:0 "$d/one"; chown 65534:65534 "$d/dir/medium"
    touch -h -d '1970-01-01 00:00:00 UTC' "$d/empty"
    touch -h -d '1969-07-20 20:17:40 UTC' "$d/one"
    touch -h -d '2038-01-19 03:14:08 UTC' "$d/block"
    touch -h -d '2099-12-31 23:59:59 UTC' "$d/dir/medium"
    touch -h -d '2020-01-01 12:34:56.123456789 UTC' "$d/small"
    touch -h -d '2001-02-03 04:05:06 UTC' "$d/link"
}

# Records what Linux reads of image $1 as $2.
answer() {
    mount -o loop,ro,utf8 -t udf "$1" "$mnt"
    python3 "$here/answer.py" "$mnt" > "$out/$2.txt"
    umount "$mnt"
    xz -9e -c "$1" > "$out/$2.udf.xz"
    echo "$2: $(wc -l < "$out/$2.txt") entries"
}

# mkudffs images: <name> <size> <mkudffs options>. Each is filled through
# Linux where Linux mounts it read-write; Linux writes UDF up to 2.01 and
# not on a VAT, and mkudffs makes UDF 2.50 and 2.60 only for write-once
# media, with a VAT, so these hold what mkudffs makes: the root directory.
while read -r name size opts; do
    [ -n "$name" ] || continue
    img=$work/$name.udf
    truncate -s "$size" "$img"
    # shellcheck disable=SC2086
    mkudffs $opts --label="$name" "$img" >/dev/null
    case "$opts" in
    *--media-type=cdr*|*--media-type=dvdr*|*--media-type=bdr*)
        # Write-once media end where their last block was written, the
        # VAT, which Linux looks for in the last block.
        python3 -c "import sys; d = open(sys.argv[1], 'rb').read(); n = len(d.rstrip(b'\\0')); open(sys.argv[1], 'r+b').truncate((n + 2047) // 2048 * 2048)" "$img"
        ;;
    esac
    bs=$(printf '%s\n' $opts | sed -n 's/^--blocksize=//p')
    mopt=loop,utf8${bs:+,bs=$bs}
    if mount -o "$mopt,rw" -t udf "$img" "$mnt" 2>/dev/null && touch "$mnt/.rw" 2>/dev/null; then
        rm -f "$mnt/.rw"
        fill "$mnt"
        filled=filled
    else
        filled=empty
    fi
    umount "$mnt" 2>/dev/null || true
    if mount -o "$mopt,ro" -t udf "$img" "$mnt" 2>/dev/null; then
        python3 "$here/answer.py" "$mnt" > "$out/$name.txt"
        umount "$mnt"
    else
        # What Linux says, for the test to read the image without it.
        { echo "# Linux does not mount it:"; dmesg 2>/dev/null | grep UDF-fs | tail -3 | sed 's/^\[[^]]*\] /# /'; } > "$out/$name.txt"
        filled=unmounted
    fi
    xz -9e -c "$img" > "$out/$name.udf.xz"
    echo "$name: $filled, $(wc -l < "$out/$name.txt") entries"
done <<'SPECS'
mkudffs-hd-0102 64M --media-type=hd --udfrev=0x0102
mkudffs-hd-0150 64M --media-type=hd --udfrev=0x0150
mkudffs-hd-0200 64M --media-type=hd --udfrev=0x0200
mkudffs-hd-0201 64M --media-type=hd --udfrev=0x0201
mkudffs-hd-0201-bs512 64M --media-type=hd --udfrev=0x0201 --blocksize=512
mkudffs-hd-0201-bs1024 64M --media-type=hd --udfrev=0x0201 --blocksize=1024
mkudffs-hd-0201-bs2048 64M --media-type=hd --udfrev=0x0201 --blocksize=2048
mkudffs-hd-0201-bs4096 64M --media-type=hd --udfrev=0x0201 --blocksize=4096
mkudffs-hd-0201-noefe 64M --media-type=hd --udfrev=0x0201 --noefe
mkudffs-hd-0201-short 64M --media-type=hd --udfrev=0x0201 --ad=short
mkudffs-hd-0201-long 64M --media-type=hd --udfrev=0x0201 --ad=long
mkudffs-hd-0201-strategy4096 64M --media-type=hd --udfrev=0x0201 --strategy=4096
mkudffs-hd-0201-unalloctable 64M --media-type=hd --udfrev=0x0201 --space=unalloctable
mkudffs-cdrw-0150 64M --media-type=cdrw --udfrev=0x0150
mkudffs-cdrw-0201 64M --media-type=cdrw --udfrev=0x0201
mkudffs-dvdrw-0201 64M --media-type=dvdrw --udfrev=0x0201
mkudffs-dvdram-0201 64M --media-type=dvdram --udfrev=0x0201
mkudffs-cdr-0150 64M --media-type=cdr --udfrev=0x0150
mkudffs-cdr-0201 64M --media-type=cdr --udfrev=0x0201
mkudffs-cdr-0201-closed 64M --media-type=cdr --udfrev=0x0201 --closed
mkudffs-dvdr-0201 64M --media-type=dvdr --udfrev=0x0201
mkudffs-cdr-0250 64M --media-type=cdr --udfrev=0x0250
mkudffs-dvdr-0250 64M --media-type=dvdr --udfrev=0x0250
mkudffs-dvdr-0260 64M --media-type=dvdr --udfrev=0x0260
mkudffs-bdr-0250 64M --media-type=bdr --udfrev=0x0250
mkudffs-bdr-0260 64M --media-type=bdr --udfrev=0x0260
SPECS

# genisoimage's UDF beside ISO 9660, as Windows' images and DVDs have it.
src=$work/src
mkdir -p "$src"
fill "$src" 2>/dev/null || true
rm -f "$src/fifo" "$src/char" "$src/block-dev"
img=$work/genisoimage.iso
genisoimage -quiet -udf -R -J -joliet-long -o "$img" "$src"
answer "$img" genisoimage
