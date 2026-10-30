/*
 * The liblzma side of hivepack-xz's comparison tests.
 *
 * It reads one request per line on stdin and answers each on one line of
 * stdout, by calling liblzma 5.8.4. The Rust tests ask the port the same
 * questions and compare the answers as text. scripts/testdata.py builds it
 * from the XZ Utils release sources, with config.h.
 *
 * Byte strings are hexadecimal, and "-" is an empty one.
 *
 *   decode <decoder> <steps> <hex>
 *       A decoder, then each step on the input <hex>. <decoder> is
 *         stream:<memlimit>:<flags>   lzma_stream_decoder
 *         auto:<memlimit>:<flags>     lzma_auto_decoder
 *         lzip:<memlimit>:<flags>     lzma_lzip_decoder
 *         alone:<memlimit>            lzma_alone_decoder
 *         raw:<filter>                lzma_raw_decoder, with one filter
 *       where a <filter> is <id>:<dict>:<lc>:<lp>:<pb>:<ext_flags>:
 *       <ext_size>:<preset>, <id> 1 for LZMA1, 2 for LZMA1EXT and 21 for
 *       LZMA2, <preset> a preset dictionary in hexadecimal. A decoder
 *       refused is answered "err <code>". The steps are comma-separated:
 *         c<in>/<out>/<action>  lzma_code with <out> bytes of output space
 *                               and that action, and as input the next
 *                               <in> bytes (fewer if fewer are left) from
 *                               where the last call stopped reading, or
 *                               with "=" for <in>, what the last call left
 *         m<limit>              lzma_memlimit_set
 *         q                     lzma_memusage, lzma_memlimit_get and
 *                               lzma_get_check
 *       Answered "ok", then a token per step: "<ret>/<read>/<written>",
 *       "m<ret>" and "q<memusage>/<memlimit>/<check>"; then
 *       " <total_in>/<total_out>" and the FNV-1a hash of all the output.
 *
 *   encode <format> <preset> <check> <hex>
 *       <hex> compressed in one call: <format> xz (lzma_easy_buffer_encode
 *       with <check>), alone (lzma_alone_encoder) or raw1 and raw2 (an
 *       LZMA1 or LZMA2 filter with the options of <preset>, as
 *       lzma_raw_buffer_encode writes them). <preset> may have bit 31 set
 *       for LZMA_PRESET_EXTREME. Answered "ok <hex>" or "err <code>".
 *
 *   memusage <filter>
 *       lzma_raw_decoder_memusage of one filter, as above.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lzma.h"

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

/*
 * Memory from calloc: lzma_get_check on a Stream decoder that has not read
 * the Stream Header yet reads stream_flags.check before anything is stored
 * there. With zeroed memory it is LZMA_CHECK_NONE, which the port answers.
 */
static void *zeroed_alloc(void *opaque, size_t nmemb, size_t size) {
    (void)opaque;
    return calloc(nmemb ? nmemb : 1, size ? size : 1);
}

static void zeroed_free(void *opaque, void *ptr) {
    (void)opaque;
    free(ptr);
}

static const lzma_allocator zeroed = {zeroed_alloc, zeroed_free, NULL};

/* The options of a filter, and its preset dictionary. */
static lzma_options_lzma options;
static unsigned char *preset;

/* A filter from its text: <id>:<dict>:<lc>:<lp>:<pb>:<ext_flags>:<ext_size>:<preset>. */
static int parse_filter(const char *text, lzma_filter *filter) {
    unsigned long id, dict, lc, lp, pb, ext_flags;
    unsigned long long ext_size;
    const char *preset_hex = text;
    size_t preset_len;
    int colons = 0;
    if (sscanf(text, "%lu:%lu:%lu:%lu:%lu:%lu:%llu:", &id, &dict, &lc, &lp, &pb, &ext_flags,
               &ext_size) != 7)
        return 0;
    /* The preset dictionary, of any length, after the seventh colon. */
    while (colons < 7 && (preset_hex = strchr(preset_hex, ':')) != NULL) {
        preset_hex++;
        colons++;
    }
    if (preset_hex == NULL || *preset_hex == '\0')
        return 0;
    memset(&options, 0, sizeof(options));
    options.dict_size = (uint32_t)dict;
    options.lc = (uint32_t)lc;
    options.lp = (uint32_t)lp;
    options.pb = (uint32_t)pb;
    options.ext_flags = (uint32_t)ext_flags;
    options.ext_size_low = (uint32_t)ext_size;
    options.ext_size_high = (uint32_t)(ext_size >> 32);
    free(preset);
    preset = unhex(preset_hex, &preset_len);
    options.preset_dict = preset_len ? preset : NULL;
    options.preset_dict_size = (uint32_t)preset_len;
    filter[0].id = id == 1 ? LZMA_FILTER_LZMA1 : id == 2 ? LZMA_FILTER_LZMA1EXT : LZMA_FILTER_LZMA2;
    filter[0].options = &options;
    filter[1].id = LZMA_VLI_UNKNOWN;
    filter[1].options = NULL;
    return 1;
}

/* The number of output bytes the steps can ask for, at most. */
static size_t output_space(const char *steps) {
    size_t total = 0;
    const char *p = steps;
    while (*p) {
        if (*p == 'c') {
            const char *slash = strchr(p, '/');
            if (slash)
                total += strtoul(slash + 1, NULL, 10);
        }
        p = strchr(p, ',');
        if (!p)
            break;
        p++;
    }
    return total;
}

static void do_decode(const char *decoder, const char *steps, const char *data_hex) {
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_filter filters[2];
    unsigned char *data, *out;
    size_t len, space, consumed = 0, written = 0;
    unsigned long long memlimit = 0;
    unsigned long flags = 0;
    lzma_ret ret;
    const char *p;

    strm.allocator = &zeroed;
    if (sscanf(decoder, "stream:%llu:%lu", &memlimit, &flags) == 2)
        ret = lzma_stream_decoder(&strm, memlimit, (uint32_t)flags);
    else if (sscanf(decoder, "auto:%llu:%lu", &memlimit, &flags) == 2)
        ret = lzma_auto_decoder(&strm, memlimit, (uint32_t)flags);
    else if (sscanf(decoder, "lzip:%llu:%lu", &memlimit, &flags) == 2)
        ret = lzma_lzip_decoder(&strm, memlimit, (uint32_t)flags);
    else if (sscanf(decoder, "alone:%llu", &memlimit) == 1)
        ret = lzma_alone_decoder(&strm, memlimit);
    else if (strncmp(decoder, "raw:", 4) == 0 && parse_filter(decoder + 4, filters))
        ret = lzma_raw_decoder(&strm, filters);
    else {
        puts("bad");
        return;
    }
    if (ret != LZMA_OK) {
        printf("err %d\n", ret);
        lzma_end(&strm);
        return;
    }
    data = unhex(data_hex, &len);
    space = output_space(steps);
    out = malloc(space + 1);
    strm.next_in = data;
    strm.avail_in = 0;

    fputs("ok", stdout);
    p = steps;
    while (*p) {
        if (*p == 'c') {
            unsigned long room;
            int action;
            size_t before_in, before_out;
            const char *q = p + 1;
            if (*q == '=') {
                q++;
            } else {
                char *end;
                unsigned long in = strtoul(q, &end, 10);
                size_t avail = in < len - consumed ? in : len - consumed;
                strm.next_in = data + consumed;
                strm.avail_in = avail;
                q = end;
            }
            if (sscanf(q, "/%lu/%d", &room, &action) != 2)
                break;
            strm.next_out = out + written;
            strm.avail_out = room;
            before_in = strm.avail_in;
            before_out = strm.avail_out;
            ret = lzma_code(&strm, (lzma_action)action);
            consumed += before_in - strm.avail_in;
            written += before_out - strm.avail_out;
            printf(" %d/%lu/%lu", ret, (unsigned long)(before_in - strm.avail_in),
                   (unsigned long)(before_out - strm.avail_out));
        } else if (*p == 'm') {
            unsigned long long limit = strtoull(p + 1, NULL, 10);
            printf(" m%d", lzma_memlimit_set(&strm, limit));
        } else if (*p == 'q') {
            printf(" q%llu/%llu/%d", (unsigned long long)lzma_memusage(&strm),
                   (unsigned long long)lzma_memlimit_get(&strm), lzma_get_check(&strm));
        }
        p = strchr(p, ',');
        if (!p)
            break;
        p++;
    }
    printf(" %llu/%llu %016llx\n", (unsigned long long)strm.total_in,
           (unsigned long long)strm.total_out, fnv64(out, written));
    lzma_end(&strm);
    free(data);
    free(out);
}

static void do_encode(const char *format, unsigned long preset_level, int check, const char *data_hex) {
    unsigned char *data, *out;
    size_t len, cap, out_pos = 0;
    lzma_ret ret;

    data = unhex(data_hex, &len);
    cap = len + len / 2 + 4096;
    out = malloc(cap);
    if (strcmp(format, "xz") == 0) {
        ret = lzma_easy_buffer_encode((uint32_t)preset_level, (lzma_check)check, NULL, data, len, out,
                                      &out_pos, cap);
    } else {
        lzma_options_lzma opt;
        lzma_filter filters[2];
        if (lzma_lzma_preset(&opt, (uint32_t)preset_level)) {
            printf("err %d\n", LZMA_OPTIONS_ERROR);
            free(data);
            free(out);
            return;
        }
        if (strcmp(format, "alone") == 0) {
            lzma_stream strm = LZMA_STREAM_INIT;
            ret = lzma_alone_encoder(&strm, &opt);
            if (ret == LZMA_OK) {
                strm.next_in = data;
                strm.avail_in = len;
                strm.next_out = out;
                strm.avail_out = cap;
                ret = lzma_code(&strm, LZMA_FINISH);
                out_pos = cap - strm.avail_out;
                if (ret == LZMA_STREAM_END)
                    ret = LZMA_OK;
            }
            lzma_end(&strm);
        } else {
            filters[0].id = strcmp(format, "raw1") == 0 ? LZMA_FILTER_LZMA1 : LZMA_FILTER_LZMA2;
            filters[0].options = &opt;
            filters[1].id = LZMA_VLI_UNKNOWN;
            ret = lzma_raw_buffer_encode(filters, NULL, data, len, out, &out_pos, cap);
        }
    }
    if (ret != LZMA_OK)
        printf("err %d\n", ret);
    else {
        fputs("ok ", stdout);
        put_hex(out, out_pos);
        putchar('\n');
    }
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
        if (count == 4 && strcmp(words[0], "decode") == 0)
            do_decode(words[1], words[2], words[3]);
        else if (count == 5 && strcmp(words[0], "encode") == 0)
            do_encode(words[1], strtoul(words[2], NULL, 10), atoi(words[3]), words[4]);
        else if (count == 2 && strcmp(words[0], "memusage") == 0) {
            lzma_filter filters[2];
            if (parse_filter(words[1], filters))
                printf("%llu\n", (unsigned long long)lzma_raw_decoder_memusage(filters));
            else
                puts("bad");
        } else
            puts("bad");
        fflush(stdout);
    }
    free(line);
    return 0;
}
