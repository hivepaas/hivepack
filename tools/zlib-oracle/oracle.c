/*
 * The zlib side of hivepack-deflate's comparison tests.
 *
 * It reads one request per line on stdin and answers each on one line of
 * stdout, by calling zlib 1.3.2. The Rust tests ask the port the same
 * questions and compare the answers as text. scripts/testdata.py builds it
 * from the zlib release sources.
 *
 * Byte strings are hexadecimal, and "-" is an empty one. A request zlib
 * refuses at the start is answered "err <code>".
 *
 *   inflate <windowBits> <head> <dict> <steps> <hex>
 *       inflateInit2(windowBits), then each step on the stream <hex>, which
 *       is given to the steps in order. The steps are comma-separated:
 *         i<in>/<out>/<flush>  inflate() with the next <in> bytes of input
 *                              (fewer if fewer are left), <out> bytes of
 *                              output space after what was written so far,
 *                              and that flush (0 to 6)
 *         s<in>                inflateSync() with the next <in> bytes
 *         p<bits>/<value>      inflatePrime(bits, value)
 *         d                    inflateSetDictionary(<dict>)
 *         v<check>             inflateValidate(check)
 *       <head> is "-", or "<extra_max>/<name_max>/<comm_max>": a gz_header
 *       with buffers of those sizes is given to inflateGetHeader first.
 *       Answered "ok", then a token per step:
 *         i: <ret>/<read>/<written>/<data_type>/<inflateMark>/<msg>
 *         s: <ret>/<read>
 *         p, d, v: <ret>
 *       where <msg> is strm.msg in hexadecimal, or "-" when null; then
 *       "<total_in>/<total_out>/<adler>", the FNV-1a hash of all the output,
 *       and with <head>, "h<ret of inflateGetHeader>" followed by
 *       "/<text>/<time>/<xflags>/<os>/<extra_len>/<hcrc>/<done>/<extra>/
 *       <name>/<comment>", the buffers in full or "null" if inflate() set
 *       them to Z_NULL.
 *
 *   deflate <level> <windowBits> <memLevel> <strategy> <dict> <pieces> <hex>
 *       deflateInit2, deflateSetDictionary(<dict>) unless it is "-", then
 *       <hex> compressed in comma-separated pieces <len>/<flush>: each
 *       piece's bytes with that flush (0 to 5), deflate() called until it
 *       leaves output space unused. After the pieces, Z_FINISH until
 *       Z_STREAM_END. Answered "ok <stream>".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zlib.h"

static unsigned char *unhex(const char *text, size_t *len) {
    size_t n, i;
    unsigned char *bytes;
    if (strcmp(text, "-") == 0) {
        *len = 0;
        return malloc(1);
    }
    n = strlen(text) / 2;
    bytes = malloc(n + 1);
    for (i = 0; i < n; i++) {
        unsigned value;
        sscanf(text + 2 * i, "%2x", &value);
        bytes[i] = (unsigned char)value;
    }
    *len = n;
    return bytes;
}

static void put_hex(const unsigned char *bytes, size_t len) {
    size_t i;
    if (len == 0) {
        fputs("-", stdout);
        return;
    }
    for (i = 0; i < len; i++)
        printf("%02x", bytes[i]);
}

static unsigned long long fnv64(const unsigned char *bytes, size_t len) {
    unsigned long long hash = 0xcbf29ce484222325ULL;
    size_t i;
    for (i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 0x00000100000001b3ULL;
    }
    return hash;
}

/* The number of output bytes the steps can ask for, at most. */
static size_t output_space(const char *steps) {
    size_t total = 0;
    const char *p = steps;
    while (*p) {
        if (*p == 'i') {
            unsigned long in, out;
            int flush;
            if (sscanf(p, "i%lu/%lu/%d", &in, &out, &flush) == 3)
                total += out;
        }
        p = strchr(p, ',');
        if (!p)
            break;
        p++;
    }
    return total;
}

static void do_inflate(int window_bits, const char *head_spec, const char *dict_hex,
                       const char *steps, const char *data_hex) {
    z_stream strm;
    gz_header head;
    unsigned char *data, *dict, *out, *extra = NULL, *name = NULL, *comment = NULL;
    size_t len, dict_len, space, consumed = 0, written = 0;
    unsigned extra_max = 0, name_max = 0, comm_max = 0;
    int ret, head_ret = 0, want_head = strcmp(head_spec, "-") != 0;
    const char *p;

    memset(&strm, 0, sizeof(strm));
    ret = inflateInit2(&strm, window_bits);
    if (ret != Z_OK) {
        printf("err %d\n", ret);
        return;
    }
    data = unhex(data_hex, &len);
    dict = unhex(dict_hex, &dict_len);
    space = output_space(steps);
    out = malloc(space + 1);
    if (want_head) {
        sscanf(head_spec, "%u/%u/%u", &extra_max, &name_max, &comm_max);
        memset(&head, 0, sizeof(head));
        extra = calloc(extra_max + 1, 1);
        name = calloc(name_max + 1, 1);
        comment = calloc(comm_max + 1, 1);
        head.extra = extra_max ? extra : Z_NULL;
        head.extra_max = extra_max;
        head.name = name_max ? name : Z_NULL;
        head.name_max = name_max;
        head.comment = comm_max ? comment : Z_NULL;
        head.comm_max = comm_max;
        head_ret = inflateGetHeader(&strm, &head);
    }

    fputs("ok", stdout);
    p = steps;
    while (*p) {
        unsigned long in, room;
        int flush, bits, value, check;
        size_t avail;
        if (*p == 'i' && sscanf(p, "i%lu/%lu/%d", &in, &room, &flush) == 3) {
            avail = in < len - consumed ? in : len - consumed;
            strm.next_in = data + consumed;
            strm.avail_in = (uInt)avail;
            strm.next_out = out + written;
            strm.avail_out = (uInt)room;
            ret = inflate(&strm, flush);
            consumed += avail - strm.avail_in;
            printf(" %d/%lu/%lu/%d/%ld/", ret, (unsigned long)(avail - strm.avail_in),
                   (unsigned long)(room - strm.avail_out), strm.data_type, inflateMark(&strm));
            written += room - strm.avail_out;
            if (strm.msg)
                put_hex((const unsigned char *)strm.msg, strlen(strm.msg));
            else
                fputs("-", stdout);
        } else if (*p == 's' && sscanf(p, "s%lu", &in) == 1) {
            avail = in < len - consumed ? in : len - consumed;
            strm.next_in = data + consumed;
            strm.avail_in = (uInt)avail;
            ret = inflateSync(&strm);
            consumed += avail - strm.avail_in;
            printf(" %d/%lu", ret, (unsigned long)(avail - strm.avail_in));
        } else if (*p == 'p' && sscanf(p, "p%d/%d", &bits, &value) == 2) {
            printf(" %d", inflatePrime(&strm, bits, value));
        } else if (*p == 'd') {
            printf(" %d", inflateSetDictionary(&strm, dict, (uInt)dict_len));
        } else if (*p == 'v' && sscanf(p, "v%d", &check) == 1) {
            printf(" %d", inflateValidate(&strm, check));
        } else {
            printf(" bad\n");
            goto done;
        }
        p = strchr(p, ',');
        if (!p)
            break;
        p++;
    }
    printf(" %lu/%lu/%lu %016llx", strm.total_in, strm.total_out, strm.adler,
           fnv64(out, written));
    if (want_head) {
        printf(" h%d", head_ret);
        if (head_ret == Z_OK) {
            printf("/%d/%lu/%d/%d/%u/%d/%d/", head.text, head.time, head.xflags, head.os,
                   head.extra_len, head.hcrc, head.done);
            if (head.extra) put_hex(extra, extra_max); else fputs("null", stdout);
            fputs("/", stdout);
            if (head.name) put_hex(name, name_max); else fputs("null", stdout);
            fputs("/", stdout);
            if (head.comment) put_hex(comment, comm_max); else fputs("null", stdout);
        }
    }
    putchar('\n');
done:
    inflateEnd(&strm);
    free(data);
    free(dict);
    free(out);
    free(extra);
    free(name);
    free(comment);
}

static void do_deflate(int level, int window_bits, int mem_level, int strategy,
                       const char *dict_hex, const char *pieces, const char *data_hex) {
    z_stream strm;
    unsigned char *data, *dict, *out;
    size_t len, dict_len, space, consumed = 0, written = 0, npieces = 1;
    const char *p;
    int ret;

    memset(&strm, 0, sizeof(strm));
    ret = deflateInit2(&strm, level, Z_DEFLATED, window_bits, mem_level, strategy);
    if (ret != Z_OK) {
        printf("err %d\n", ret);
        return;
    }
    data = unhex(data_hex, &len);
    dict = unhex(dict_hex, &dict_len);
    if (dict_len) {
        ret = deflateSetDictionary(&strm, dict, (uInt)dict_len);
        if (ret != Z_OK) {
            printf("err %d\n", ret);
            goto done;
        }
    }
    for (p = pieces; *p; p++)
        npieces += *p == ',';
    space = deflateBound(&strm, len) + 16 * npieces + 1024;
    out = malloc(space);

    p = pieces;
    while (*p && strcmp(p, "-") != 0) {
        unsigned long piece;
        int flush;
        if (sscanf(p, "%lu/%d", &piece, &flush) != 2) {
            printf("bad\n");
            free(out);
            goto done;
        }
        if (piece > len - consumed)
            piece = len - consumed;
        strm.next_in = data + consumed;
        strm.avail_in = (uInt)piece;
        do {
            strm.next_out = out + written;
            strm.avail_out = (uInt)(space - written);
            ret = deflate(&strm, flush);
            written = space - strm.avail_out;
        } while (strm.avail_out == 0 && ret == Z_OK);
        consumed += piece - strm.avail_in;
        p = strchr(p, ',');
        if (!p)
            break;
        p++;
    }
    strm.next_in = data + consumed;
    strm.avail_in = (uInt)(len - consumed);
    do {
        strm.next_out = out + written;
        strm.avail_out = (uInt)(space - written);
        ret = deflate(&strm, Z_FINISH);
        written = space - strm.avail_out;
    } while (ret == Z_OK);
    if (ret != Z_STREAM_END) {
        printf("err %d\n", ret);
    } else {
        fputs("ok ", stdout);
        put_hex(out, written);
        putchar('\n');
    }
    free(out);
done:
    deflateEnd(&strm);
    free(data);
    free(dict);
}

int main(void) {
    size_t cap = 1 << 20;
    char *line = malloc(cap);
    while (fgets(line, (int)cap, stdin)) {
        size_t n = strlen(line);
        char *words[8];
        int count = 0;
        char *word;
        while (n == cap - 1 && line[n - 1] != '\n') {
            cap *= 2;
            line = realloc(line, cap);
            if (!fgets(line + n, (int)(cap - n), stdin))
                break;
            n = strlen(line);
        }
        if (n && line[n - 1] == '\n')
            line[--n] = '\0';
        for (word = strtok(line, " "); word && count < 8; word = strtok(NULL, " "))
            words[count++] = word;
        if (count == 6 && strcmp(words[0], "inflate") == 0)
            do_inflate(atoi(words[1]), words[2], words[3], words[4], words[5]);
        else if (count == 8 && strcmp(words[0], "deflate") == 0)
            do_deflate(atoi(words[1]), atoi(words[2]), atoi(words[3]), atoi(words[4]), words[5],
                       words[6], words[7]);
        else
            puts("bad");
        fflush(stdout);
    }
    free(line);
    return 0;
}
