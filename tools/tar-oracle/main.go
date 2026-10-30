// The Go side of hivepack-tar's comparison tests.
//
// It reads one request per line on stdin and answers each on one line of
// stdout, with Go's archive/tar, which hivepack-tar ports. The Rust tests
// ask the port the same questions and compare the answers as text.
// scripts/testdata.py builds it with the Go toolchain go.mod names.
//
// Byte strings are hexadecimal, and "-" is an empty one.
//
//	read <archive>
//	    Every entry of <archive>, read with tar.Reader through a plain
//	    io.Reader (so that nothing is skipped by seeking), and up to 8 MiB
//	    of its data with io.ReadAll (sparse files can be terabytes of
//	    holes). Answered with one field per entry, separated by "|",
//	    then the end: "eof", or the error Next returned. An entry is
//	    "<typeflag>,<name>,<linkname>,<size>,<mode>,<uid>,<gid>,<uname>,
//	    <gname>,<mtime>,<atime>,<ctime>,<devmajor>,<devminor>,<format>,
//	    <pax>,<xattrs>,<data length>,<data>,<data error>": names in hex,
//	    times as "<seconds>.<nanoseconds>" or "-" for Go's zero time, the
//	    format's bits, the PAX records and extended attributes as the
//	    SHA-256 of "key=value\n" in key order (first 8 bytes), the data's
//	    SHA-256 likewise, and the error that ended the data ("-" if none).
//	    Errors are "header", "field-too-long", "sparse-too-long",
//	    "miss-data", "unref-data", "unexpected-eof", or "other".
//
//	write <headers>
//	    An archive written by tar.Writer from <headers>, a JSON list of
//	    tar.Header, each followed by Size bytes of data whose byte i is
//	    i*7+len(Name) (mod 256), for the types that have data. Answered
//	    "ok <archive>", or "err" if the Writer refuses.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

func unhex(s string) []byte {
	if s == "-" {
		return []byte{}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func hx(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return hex.EncodeToString(b)
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func records(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m[k])
		b.WriteByte('\n')
	}
	return digest(b.Bytes())
}

func when(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return fmt.Sprintf("%d.%d", t.Unix(), t.Nanosecond())
}

func name(err error) string {
	switch {
	case err == nil:
		return "-"
	case errors.Is(err, tar.ErrHeader):
		return "header"
	case errors.Is(err, tar.ErrFieldTooLong):
		return "field-too-long"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected-eof"
	}
	switch err.Error() {
	case "archive/tar: sparse map too long":
		return "sparse-too-long"
	case "archive/tar: sparse file references non-existent data":
		return "miss-data"
	case "archive/tar: sparse file contains unreferenced data":
		return "unref-data"
	}
	return "other"
}

// maxData is how much of an entry's data is read.
const maxData = 8 << 20

func read(archive []byte) string {
	tr := tar.NewReader(struct{ io.Reader }{bytes.NewReader(archive)})
	var out []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			out = append(out, "eof")
			break
		}
		if err != nil {
			out = append(out, name(err))
			break
		}
		data, derr := io.ReadAll(io.LimitReader(tr, maxData))
		out = append(out, fmt.Sprintf("%d,%s,%s,%d,%d,%d,%d,%s,%s,%s,%s,%s,%d,%d,%d,%s,%s,%d,%s,%s",
			h.Typeflag, hx([]byte(h.Name)), hx([]byte(h.Linkname)), h.Size, h.Mode, h.Uid, h.Gid,
			hx([]byte(h.Uname)), hx([]byte(h.Gname)), when(h.ModTime), when(h.AccessTime),
			when(h.ChangeTime), h.Devmajor, h.Devminor, int(h.Format), records(h.PAXRecords),
			records(h.Xattrs), len(data), digest(data), name(derr)))
	}
	return strings.Join(out, "|")
}

func write(spec []byte) string {
	var headers []tar.Header
	if err := json.Unmarshal(spec, &headers); err != nil {
		return "bad"
	}
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for i := range headers {
		h := &headers[i]
		if err := tw.WriteHeader(h); err != nil {
			return "err"
		}
		switch h.Typeflag {
		case tar.TypeLink, tar.TypeSymlink, tar.TypeChar, tar.TypeBlock, tar.TypeDir, tar.TypeFifo:
			continue
		}
		data := make([]byte, h.Size)
		for j := range data {
			data[j] = byte(j*7 + len(h.Name))
		}
		if _, err := tw.Write(data); err != nil {
			return "err"
		}
	}
	if err := tw.Close(); err != nil {
		return "err"
	}
	return "ok " + hx(b.Bytes())
}

func main() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriter(os.Stdout)
	for {
		line, err := in.ReadString('\n')
		line = strings.TrimRight(line, "\n")
		if line != "" {
			words := strings.Split(line, " ")
			switch {
			case words[0] == "read" && len(words) == 2:
				fmt.Fprintln(out, read(unhex(words[1])))
			case words[0] == "write" && len(words) == 2:
				fmt.Fprintln(out, write(unhex(words[1])))
			default:
				fmt.Fprintln(out, "bad")
			}
			out.Flush()
		}
		if err != nil {
			return
		}
	}
}
