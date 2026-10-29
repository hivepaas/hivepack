/*
 * The libbzip2 side of hivepack-bzip2's comparison tests.
 *
 * It reads one request per line on stdin and answers each on one line of
 * stdout, by calling libbzip2 1.0.8. The Rust tests ask the port the same
 * questions and compare the answers as text. scripts/testdata.py builds it
 * from the bzip2 release sources.
 *
 * Byte strings are hexadecimal, and "-" is an empty one. A request
 * libbzip2 refuses at the start is answered "err <code>".
 *
 *   compress <blockSize100k> <workFactor> <steps> <hex>
 *       BZ2_bzCompressInit(blockSize100k, 0, workFactor), then each step
 *       on the input <hex>. The steps are comma-separated
 *       c<in>/<out>/<action>: BZ2_bzCompress with <out> bytes of output
 *       space and that action (0 to 2), and as input either the next <in>
 *       bytes (fewer if fewer are left) from where the last call stopped
 *       reading, or, with "=" for <in>, what the last call left of its
 *       input, as a caller that keeps its buffer leaves next_in and
 *       avail_in. Answered "ok", then " <ret>/<read>/<written>" for each
 *       step, then " <total_in>/<total_out>" and the FNV-1a hash of all
 *       the output.
 *
 *   decompress <small> <steps> <hex>
 *       BZ2_bzDecompressInit(0, small), then each step d<in>/<out>, as
 *       above, with BZ2_bzDecompress. The steps after the first error are
 *       not run: libbzip2 allows nothing after one but
 *       BZ2_bzDecompressEnd. Answered as compress, with a token for each
 *       step run.
 *
 *   buffc <blockSize100k> <workFactor> <destLen> <hex>
 *   buffd <small> <destLen> <hex>
 *       BZ2_bzBuffToBuffCompress and BZ2_bzBuffToBuffDecompress, with
 *       verbosity 0, into <destLen> bytes. Answered
 *       "<ret> <destLen> <hash>": what they returned, the destLen they
 *       left, and the FNV-1a hash of that many bytes of the output.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bzlib.h"

static int nibble(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return c - 'A' + 10;
}

static unsigned char *unhex(const char *text, size_t *len) {
    size_t n, i;
    unsigned char *bytes;
    if (strcmp(text, "-") == 0) {
        *len = 0;
        return malloc(1);
    }
    n = strlen(text) / 2;
    bytes = malloc(n + 1);
    for (i = 0; i < n; i++)
        bytes[i] = (unsigned char)(nibble(text[2 * i]) << 4 | nibble(text[2 * i + 1]));
    *len = n;
    return bytes;
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
        const char *slash = strchr(p, '/');
        if (slash)
            total += strtoul(slash + 1, NULL, 10);
        p = strchr(p, ',');
        if (!p)
            break;
        p++;
    }
    return total;
}

/*
 * The input of a step: <in> is "=" or a number, as the requests above
 * say. Sets next_in and avail_in, and returns what follows <in>.
 */
static const char *step_input(const char *p, bz_stream *strm, unsigned char *data, size_t len,
                              size_t consumed) {
    if (*p == '=')
        return p + 1;
    {
        char *end;
        unsigned long in = strtoul(p, &end, 10);
        size_t avail = in < len - consumed ? in : len - consumed;
        strm->next_in = (char *)(data + consumed);
        strm->avail_in = (unsigned int)avail;
        return end;
    }
}

static void do_compress(int block_size, int work_factor, const char *steps, const char *data_hex) {
    bz_stream strm;
    unsigned char *data, *out;
    size_t len, space, consumed = 0, written = 0;
    int ret;
    const char *p;

    memset(&strm, 0, sizeof(strm));
    ret = BZ2_bzCompressInit(&strm, block_size, 0, work_factor);
    if (ret != BZ_OK) {
        printf("err %d\n", ret);
        return;
    }
    data = unhex(data_hex, &len);
    space = output_space(steps);
    out = malloc(space + 1);
    strm.next_in = (char *)data;
    strm.avail_in = 0;

    fputs("ok", stdout);
    p = steps;
    while (*p == 'c') {
        unsigned long room;
        int action;
        unsigned int before_in;
        p = step_input(p + 1, &strm, data, len, consumed);
        if (sscanf(p, "/%lu/%d", &room, &action) != 2)
            break;
        strm.next_out = (char *)(out + written);
        strm.avail_out = (unsigned int)room;
        before_in = strm.avail_in;
        ret = BZ2_bzCompress(&strm, action);
        consumed += before_in - strm.avail_in;
        printf(" %d/%lu/%lu", ret, (unsigned long)(before_in - strm.avail_in),
               (unsigned long)(room - strm.avail_out));
        written += room - strm.avail_out;
        p = strchr(p, ',');
        if (!p)
            break;
        p++;
    }
    printf(" %llu/%llu %016llx\n",
           (unsigned long long)strm.total_in_lo32 | (unsigned long long)strm.total_in_hi32 << 32,
           (unsigned long long)strm.total_out_lo32 | (unsigned long long)strm.total_out_hi32 << 32,
           fnv64(out, written));
    BZ2_bzCompressEnd(&strm);
    free(data);
    free(out);
}

static void do_decompress(int small, const char *steps, const char *data_hex) {
    bz_stream strm;
    unsigned char *data, *out;
    size_t len, space, consumed = 0, written = 0;
    int ret;
    const char *p;

    memset(&strm, 0, sizeof(strm));
    ret = BZ2_bzDecompressInit(&strm, 0, small);
    if (ret != BZ_OK) {
        printf("err %d\n", ret);
        return;
    }
    data = unhex(data_hex, &len);
    space = output_space(steps);
    out = malloc(space + 1);
    strm.next_in = (char *)data;
    strm.avail_in = 0;

    fputs("ok", stdout);
    p = steps;
    while (*p == 'd') {
        unsigned long room;
        unsigned int before_in;
        p = step_input(p + 1, &strm, data, len, consumed);
        if (sscanf(p, "/%lu", &room) != 1)
            break;
        strm.next_out = (char *)(out + written);
        strm.avail_out = (unsigned int)room;
        before_in = strm.avail_in;
        ret = BZ2_bzDecompress(&strm);
        consumed += before_in - strm.avail_in;
        printf(" %d/%lu/%lu", ret, (unsigned long)(before_in - strm.avail_in),
               (unsigned long)(room - strm.avail_out));
        written += room - strm.avail_out;
        if (ret < 0)
            break;
        p = strchr(p, ',');
        if (!p)
            break;
        p++;
    }
    printf(" %llu/%llu %016llx\n",
           (unsigned long long)strm.total_in_lo32 | (unsigned long long)strm.total_in_hi32 << 32,
           (unsigned long long)strm.total_out_lo32 | (unsigned long long)strm.total_out_hi32 << 32,
           fnv64(out, written));
    BZ2_bzDecompressEnd(&strm);
    free(data);
    free(out);
}

static void do_buff(int compress, int a, int b, unsigned int dest_len, const char *data_hex) {
    unsigned char *data, *out;
    size_t len;
    int ret;

    data = unhex(data_hex, &len);
    out = malloc(dest_len + 1);
    if (compress)
        ret = BZ2_bzBuffToBuffCompress((char *)out, &dest_len, (char *)data, (unsigned int)len, a,
                                       0, b);
    else
        ret = BZ2_bzBuffToBuffDecompress((char *)out, &dest_len, (char *)data, (unsigned int)len,
                                         a, 0);
    printf("%d %u %016llx\n", ret, dest_len, fnv64(out, ret == BZ_OK ? dest_len : 0));
    free(data);
    free(out);
}

int main(void) {
    size_t cap = 1 << 20;
    char *line = malloc(cap);
    while (fgets(line, (int)cap, stdin)) {
        size_t n = strlen(line);
        char *words[6];
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
        for (word = strtok(line, " "); word && count < 6; word = strtok(NULL, " "))
            words[count++] = word;
        if (count == 5 && strcmp(words[0], "compress") == 0)
            do_compress(atoi(words[1]), atoi(words[2]), words[3], words[4]);
        else if (count == 4 && strcmp(words[0], "decompress") == 0)
            do_decompress(atoi(words[1]), words[2], words[3]);
        else if (count == 5 && strcmp(words[0], "buffc") == 0)
            do_buff(1, atoi(words[1]), atoi(words[2]), (unsigned int)strtoul(words[3], NULL, 10),
                    words[4]);
        else if (count == 4 && strcmp(words[0], "buffd") == 0)
            do_buff(0, atoi(words[1]), 0, (unsigned int)strtoul(words[2], NULL, 10), words[3]);
        else
            puts("bad");
        fflush(stdout);
    }
    free(line);
    return 0;
}
