// The Go side of hivepack's comparison tests for age.
//
// It reads one request per line on stdin and answers each on one line of
// stdout, with the code age v1.3.2 runs: its primitives from Go's standard
// library and golang.org/x/crypto v0.55.0, the release age v1.3.2 requires.
// The Rust tests ask the port the same questions and compare the answers as
// text. scripts/testdata.py builds it with the Go toolchain; go.sum pins
// what it is built from.
//
// Byte strings are hexadecimal, and "-" is an empty one.
//
//	sha256 <data>
//	sha512 <data>
//	    Answered "ok <digest>".
//
//	hmac256 <key> <data>
//	hmac512 <key> <data>
//	    HMAC-SHA256 or HMAC-SHA512. Answered "ok <mac>".
//
//	pbkdf2 <iterations> <length> <password> <salt>
//	    PBKDF2-HMAC-SHA256 (crypto/pbkdf2). Answered "ok <key>".
//
//	hkdf <salt> <ikm> <info> <length>
//	    HKDF-SHA256 as age uses it (x/crypto/hkdf), <salt> "none" for none.
//	    Answered "ok <key>", or "err" past 255 × 32 bytes.
//
//	chacha20 <key> <nonce> <counter> <data>
//	    <data> XORed with ChaCha20 (x/crypto/chacha20) from block
//	    <counter>. Answered "ok <data>".
//
//	seal <key> <nonce> <aad> <data>
//	    ChaCha20-Poly1305 (x/crypto/chacha20poly1305). Answered
//	    "ok <ciphertext and tag>".
//
//	open <key> <nonce> <aad> <ciphertext and tag>
//	    Answered "ok <plaintext>", or "err" if the tag does not match.
//
//	x25519 <scalar> <point>
//	    X25519 (x/crypto/curve25519). Answered "ok <point>", or "err" for an
//	    all-zero result, which x/crypto refuses.
//
//	scrypt <log2 N> <r> <p> <length> <password> <salt>
//	    x/crypto/scrypt. Answered "ok <key>", or "err" for parameters it
//	    refuses.
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
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

func ok(b []byte) string {
	if len(b) == 0 {
		return "ok -"
	}
	return "ok " + hex.EncodeToString(b)
}

func number(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return n
}

func digest(h hash.Hash, data []byte) string {
	h.Write(data)
	return ok(h.Sum(nil))
}

func answer(words []string) string {
	switch {
	case words[0] == "sha256" && len(words) == 2:
		return digest(sha256.New(), unhex(words[1]))
	case words[0] == "sha512" && len(words) == 2:
		return digest(sha512.New(), unhex(words[1]))
	case words[0] == "hmac256" && len(words) == 3:
		return digest(hmac.New(sha256.New, unhex(words[1])), unhex(words[2]))
	case words[0] == "hmac512" && len(words) == 3:
		return digest(hmac.New(sha512.New, unhex(words[1])), unhex(words[2]))
	case words[0] == "pbkdf2" && len(words) == 5:
		key, err := pbkdf2.Key(sha256.New, string(unhex(words[3])), unhex(words[4]),
			number(words[1]), number(words[2]))
		if err != nil {
			return "err"
		}
		return ok(key)
	case words[0] == "hkdf" && len(words) == 5:
		var salt []byte
		if words[1] != "none" {
			salt = unhex(words[1])
		}
		out := make([]byte, number(words[4]))
		h := hkdf.New(sha256.New, unhex(words[2]), salt, unhex(words[3]))
		if _, err := io.ReadFull(h, out); err != nil {
			return "err"
		}
		return ok(out)
	case words[0] == "chacha20" && len(words) == 5:
		c, err := chacha20.NewUnauthenticatedCipher(unhex(words[1]), unhex(words[2]))
		if err != nil {
			return "bad"
		}
		c.SetCounter(uint32(number(words[3])))
		data := unhex(words[4])
		c.XORKeyStream(data, data)
		return ok(data)
	case words[0] == "seal" && len(words) == 5:
		aead, err := chacha20poly1305.New(unhex(words[1]))
		if err != nil {
			return "bad"
		}
		return ok(aead.Seal(nil, unhex(words[2]), unhex(words[4]), unhex(words[3])))
	case words[0] == "open" && len(words) == 5:
		aead, err := chacha20poly1305.New(unhex(words[1]))
		if err != nil {
			return "bad"
		}
		plaintext, err := aead.Open(nil, unhex(words[2]), unhex(words[4]), unhex(words[3]))
		if err != nil {
			return "err"
		}
		return ok(plaintext)
	case words[0] == "x25519" && len(words) == 3:
		out, err := curve25519.X25519(unhex(words[1]), unhex(words[2]))
		if err != nil {
			return "err"
		}
		return ok(out)
	case words[0] == "scrypt" && len(words) == 7:
		logN := number(words[1])
		if logN < 0 || logN > 62 {
			return "err"
		}
		key, err := scrypt.Key(unhex(words[5]), unhex(words[6]), 1<<logN, number(words[2]),
			number(words[3]), number(words[4]))
		if err != nil {
			return "err"
		}
		return ok(key)
	}
	return "bad"
}

func main() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriter(os.Stdout)
	for {
		line, err := in.ReadString('\n')
		line = strings.TrimRight(line, "\n")
		if line != "" {
			fmt.Fprintln(out, answer(strings.Split(line, " ")))
			out.Flush()
		}
		if err != nil {
			return
		}
	}
}
