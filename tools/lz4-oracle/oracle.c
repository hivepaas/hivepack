/*
 * The liblz4 side of hivepack-lz4's comparison tests.
 *
 * It reads one request per line on stdin and answers each on one line of
 * stdout, by calling liblz4 1.10.0. The Rust tests ask the port the same
 * questions and compare the answers as text. scripts/testdata.py builds it
 * from the lz4 release sources.
 *
 * Byte strings are hexadecimal, and "-" is an empty one. Hashes are FNV-1a
 * (64 bits).
 *
 *   block <mode> <capacity> <target> <dict> <hex>
 *       Decodes the block <hex> into a buffer of <capacity> bytes, first
 *       filled with the bytes (i * 7 + 3) & 255, with the function of
 *       <mode>:
 *         s  LZ4_decompress_safe
 *         p  LZ4_decompress_safe_partial, with <target>
 *         d  LZ4_decompress_safe_usingDict, <dict> apart from the output
 *         q  LZ4_decompress_safe_partial_usingDict, the same, with <target>
 *         x  LZ4_decompress_safe_usingDict, <dict> right before the output
 *            in the same buffer
 *         y  LZ4_decompress_safe_partial_usingDict, the same, with <target>
 *       Answered "<ret> <hash>": what the function returned, and the hash
 *       of the whole buffer of <capacity> bytes, which shows what it wrote
 *       past what it decoded too.
 *
 *   stream <dict> <capacity> <blocks>
 *       LZ4_setStreamDecode with <dict> (in its own buffer), then
 *       LZ4_decompress_safe_continue for each block of the comma-separated
 *       <blocks>, each decoded right after the one before, in one buffer,
 *       with <capacity> bytes of room. Answered "ok", then "<ret>/<hash>"
 *       for each block, the hash of what it decoded, up to the first
 *       error.
 *
 *   frame <dict> <skip> <steps> <hex>
 *       A decompression context, then each step on the input <hex>. The
 *       steps are comma-separated:
 *         d<in>/<out>  LZ4F_decompress, or LZ4F_decompress_usingDict with
 *                      <dict> when it is not "-", with <out> bytes of output
 *                      space, the next <in> bytes of input (fewer if fewer
 *                      are left) from where the last call stopped reading,
 *                      and skipChecksums <skip> (0 or 1).
 *         i<in>        LZ4F_getFrameInfo, with the next <in> bytes.
 *         r            LZ4F_resetDecompressionContext.
 *       Answered "ok", then " <ret>/<read>/<written>" for each d step,
 *       " <ret>/<read>/<info>" for each i step and " r" for each r, then
 *       the hash of all the output. <ret> is the hint, or the error's name.
 *       <info> is the frame info's fields, colon-separated: blockSizeID,
 *       blockMode, contentChecksumFlag, frameType, contentSize, dictID and
 *       blockChecksumFlag. After an error, which leaves the context in an
 *       undefined state, the steps that follow are not run.
 *
 *   compress <accel> <capacity> <blocks>
 *       One state, then for each block of the comma-separated <blocks>,
 *       compressed alone into a buffer of <capacity> bytes filled with the
 *       pattern above: LZ4_compress_fast_extState for the first, and
 *       LZ4_compress_fast_extState_fastReset with the same state for the
 *       others, with acceleration <accel>. Answered "ok", then
 *       " <ret>/<hash>" for each, the hash of the whole buffer.
 *
 *   destsize <accel> <capacity> <hex>
 *       LZ4_compress_destSize_extState into <capacity> bytes. Answered
 *       "<ret> <srcSize> <hash>".
 *
 *   cstream <dict> <how> <accel> <capacity> <blocks>
 *       A stream, and the dictionary <dict> loaded into it (<how> l:
 *       LZ4_loadDict, s: LZ4_loadDictSlow, a: loaded into another stream
 *       with LZ4_loadDictSlow and attached with LZ4_attach_dictionary to
 *       this one, reset with LZ4_resetStream_fast), then for each block,
 *       each in its own buffer, LZ4_compress_fast_continue into <capacity>
 *       bytes, then LZ4_saveDict of 64 KB into a buffer apart. Answered as
 *       compress.
 *
 *   hc <level> <capacity> <blocks>
 *       As compress, with LZ4_compress_HC_extStateHC and its _fastReset form
 *       at <level>.
 *
 *   hcdest <level> <capacity> <hex>
 *       LZ4_compress_HC_destSize. Answered as destsize.
 *
 *   hcstream <dict> <how> <level> <capacity> <blocks>
 *       A stream reset at <level> (LZ4_resetStreamHC), then the dictionary
 *       loaded (<how> l: LZ4_loadDictHC; a: loaded into another stream at
 *       <level> and attached to this one, reset with LZ4_resetStreamHC_fast;
 *       f: as l, with LZ4_favorDecompressionSpeed), then each block
 *       compressed with LZ4_compress_HC_continue and the history saved with
 *       LZ4_saveDictHC, as cstream. Answered as compress.
 *
 *   header <hex>
 *       LZ4F_headerSize. Answered with the size or the error's name.
 *
 *   xxh32 <seed> <pieces> <hex>
 *       XXH32 of <hex> with <seed>, in one call, then streamed in pieces of
 *       the comma-separated sizes in <pieces> (the rest in one last
 *       piece). Answered "<one call> <streamed>", in hexadecimal.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LZ4_STATIC_LINKING_ONLY
#define LZ4F_STATIC_LINKING_ONLY
#define XXH_STATIC_LINKING_ONLY
#include "lz4.h"
#define LZ4_HC_STATIC_LINKING_ONLY
#include "lz4hc.h"
#include "lz4frame.h"
#include "xxhash.h"

static char line[1 << 26];

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

static void fill_pattern(unsigned char *buffer, size_t len) {
    size_t i;
    for (i = 0; i < len; i++)
        buffer[i] = (unsigned char)((i * 7 + 3) & 255);
}

static void do_block(const char *mode, int capacity, int target, const char *dict_hex,
                     const char *data_hex) {
    size_t len, dict_len;
    unsigned char *data = unhex(data_hex, &len);
    unsigned char *dict = unhex(dict_hex, &dict_len);
    /* The prefix modes keep the dictionary right before the output. */
    unsigned char *buffer = malloc(dict_len + (size_t)capacity + 1);
    unsigned char *dst = buffer + dict_len;
    int ret;
    memcpy(buffer, dict, dict_len);
    fill_pattern(dst, (size_t)capacity);
    switch (mode[0]) {
    case 's':
        ret = LZ4_decompress_safe((const char *)data, (char *)dst, (int)len, capacity);
        break;
    case 'p':
        ret = LZ4_decompress_safe_partial((const char *)data, (char *)dst, (int)len, target,
                                          capacity);
        break;
    case 'd':
        ret = LZ4_decompress_safe_usingDict((const char *)data, (char *)dst, (int)len, capacity,
                                            (const char *)dict, (int)dict_len);
        break;
    case 'q':
        ret = LZ4_decompress_safe_partial_usingDict((const char *)data, (char *)dst, (int)len,
                                                    target, capacity, (const char *)dict,
                                                    (int)dict_len);
        break;
    case 'x':
        ret = LZ4_decompress_safe_usingDict((const char *)data, (char *)dst, (int)len, capacity,
                                            (const char *)buffer, (int)dict_len);
        break;
    case 'y':
        ret = LZ4_decompress_safe_partial_usingDict((const char *)data, (char *)dst, (int)len,
                                                    target, capacity, (const char *)buffer,
                                                    (int)dict_len);
        break;
    default:
        printf("bad\n");
        free(data);
        free(dict);
        free(buffer);
        return;
    }
    printf("%d %016llx\n", ret, fnv64(dst, (size_t)capacity));
    free(data);
    free(dict);
    free(buffer);
}

static void do_stream(const char *dict_hex, int capacity, char *blocks) {
    size_t dict_len, count = 1, i, written = 0;
    unsigned char *dict = unhex(dict_hex, &dict_len);
    unsigned char *out;
    LZ4_streamDecode_t *stream = LZ4_createStreamDecode();
    char *p, *next;
    for (p = blocks; *p; p++)
        if (*p == ',')
            count++;
    out = malloc((size_t)capacity * count + 1);
    LZ4_setStreamDecode(stream, (const char *)dict, (int)dict_len);
    printf("ok");
    p = blocks;
    for (i = 0; i < count; i++) {
        size_t len;
        unsigned char *data;
        int ret;
        next = strchr(p, ',');
        if (next)
            *next = 0;
        data = unhex(p, &len);
        ret = LZ4_decompress_safe_continue(stream, (const char *)data, (char *)out + written,
                                           (int)len, capacity);
        printf(" %d/%016llx", ret, fnv64(out + written, ret > 0 ? (size_t)ret : 0));
        if (ret > 0)
            written += (size_t)ret;
        free(data);
        if (ret < 0)
            break;
        if (!next)
            break;
        p = next + 1;
    }
    printf("\n");
    LZ4_freeStreamDecode(stream);
    free(dict);
    free(out);
}

/* The output space all the steps can ask for. */
static size_t output_space(const char *steps) {
    size_t total = 0;
    const char *p = steps;
    while (*p) {
        if (*p == 'd') {
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

static void print_result(size_t ret) {
    if (LZ4F_isError(ret))
        printf("%s", LZ4F_getErrorName(ret));
    else
        printf("%zu", ret);
}

static void do_frame(const char *dict_hex, int skip, const char *steps, const char *data_hex) {
    size_t len, dict_len, space, consumed = 0, written = 0;
    unsigned char *data = unhex(data_hex, &len);
    /* An empty dictionary is a pointer too, which liblz4 takes as one. */
    int use_dict = strcmp(dict_hex, "-") != 0;
    unsigned char *dict = unhex(dict_hex, &dict_len);
    unsigned char *out;
    const char *p = steps;
    LZ4F_dctx *dctx;
    LZ4F_decompressOptions_t options;

    if (LZ4F_isError(LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION))) {
        printf("bad\n");
        return;
    }
    memset(&options, 0, sizeof(options));
    options.skipChecksums = (unsigned)skip;
    space = output_space(steps);
    out = malloc(space + 1);
    printf("ok");
    while (*p) {
        char *end;
        if (*p == 'r') {
            LZ4F_resetDecompressionContext(dctx);
            printf(" r");
            p++;
        } else {
            char kind = *p++;
            unsigned long in = strtoul(p, &end, 10);
            size_t avail = in < len - consumed ? in : len - consumed;
            size_t src_size = avail;
            size_t ret;
            p = end;
            if (kind == 'd') {
                unsigned long room = strtoul(p + 1, &end, 10);
                size_t dst_size = room;
                p = end;
                if (use_dict)
                    ret = LZ4F_decompress_usingDict(dctx, out + written, &dst_size,
                                                    data + consumed, &src_size, dict, dict_len,
                                                    &options);
                else
                    ret = LZ4F_decompress(dctx, out + written, &dst_size, data + consumed,
                                          &src_size, &options);
                printf(" ");
                print_result(ret);
                printf("/%zu/%zu", src_size, dst_size);
                consumed += src_size;
                written += dst_size;
            } else {
                LZ4F_frameInfo_t info;
                memset(&info, 0, sizeof(info));
                ret = LZ4F_getFrameInfo(dctx, &info, data + consumed, &src_size);
                printf(" ");
                print_result(ret);
                printf("/%zu/%d:%d:%d:%d:%llu:%u:%d", src_size, (int)info.blockSizeID,
                       (int)info.blockMode, (int)info.contentChecksumFlag, (int)info.frameType,
                       info.contentSize, info.dictID, (int)info.blockChecksumFlag);
                consumed += src_size;
            }
            if (LZ4F_isError(ret))
                break;
        }
        if (*p == ',')
            p++;
    }
    printf(" %016llx\n", fnv64(out, written));
    LZ4F_freeDecompressionContext(dctx);
    free(data);
    free(dict);
    free(out);
}

/* The comma-separated hex strings of `list`, one by one: returns the next,
 * cut out of the list, or NULL. */
static char *next_item(char **list) {
    char *item = *list, *comma;
    if (!item)
        return NULL;
    comma = strchr(item, ',');
    if (comma) {
        *comma = 0;
        *list = comma + 1;
    } else {
        *list = NULL;
    }
    return item;
}

static void do_compress(int accel, int capacity, char *blocks) {
    LZ4_stream_t *state = LZ4_createStream();
    unsigned char *out = malloc((size_t)capacity + 1);
    char *item;
    int first = 1;
    printf("ok");
    while ((item = next_item(&blocks)) != NULL) {
        size_t len;
        unsigned char *data = unhex(item, &len);
        int ret;
        fill_pattern(out, (size_t)capacity);
        if (first)
            ret = LZ4_compress_fast_extState(state, (const char *)data, (char *)out, (int)len,
                                             capacity, accel);
        else
            ret = LZ4_compress_fast_extState_fastReset(state, (const char *)data, (char *)out,
                                                       (int)len, capacity, accel);
        first = 0;
        printf(" %d/%016llx", ret, fnv64(out, (size_t)capacity));
        free(data);
    }
    printf("\n");
    LZ4_freeStream(state);
    free(out);
}

static void do_destsize(int accel, int capacity, const char *data_hex) {
    size_t len;
    unsigned char *data = unhex(data_hex, &len);
    unsigned char *out = malloc((size_t)capacity + 1);
    LZ4_stream_t *state = LZ4_createStream();
    int src_size = (int)len, ret;
    fill_pattern(out, (size_t)capacity);
    ret = LZ4_compress_destSize_extState(state, (const char *)data, (char *)out, &src_size,
                                         capacity, accel);
    printf("%d %d %016llx\n", ret, src_size, fnv64(out, (size_t)capacity));
    LZ4_freeStream(state);
    free(data);
    free(out);
}

static void do_cstream(const char *dict_hex, const char *how, int accel, int capacity,
                       char *blocks) {
    size_t dict_len;
    unsigned char *dict = unhex(dict_hex, &dict_len);
    LZ4_stream_t *stream = LZ4_createStream();
    LZ4_stream_t *dict_stream = LZ4_createStream();
    unsigned char *out = malloc((size_t)capacity + 1);
    char *safe = malloc(64 * 1024);
    char *item;
    if (how[0] == 'l')
        LZ4_loadDict(stream, (const char *)dict, (int)dict_len);
    else if (how[0] == 's')
        LZ4_loadDictSlow(stream, (const char *)dict, (int)dict_len);
    else {
        LZ4_loadDictSlow(dict_stream, (const char *)dict, (int)dict_len);
        LZ4_resetStream_fast(stream);
        LZ4_attach_dictionary(stream, dict_stream);
    }
    printf("ok");
    while ((item = next_item(&blocks)) != NULL) {
        size_t len;
        unsigned char *data = unhex(item, &len);
        int ret;
        fill_pattern(out, (size_t)capacity);
        ret = LZ4_compress_fast_continue(stream, (const char *)data, (char *)out, (int)len,
                                         capacity, accel);
        printf(" %d/%016llx", ret, fnv64(out, (size_t)capacity));
        LZ4_saveDict(stream, safe, 64 * 1024);
        free(data);
    }
    printf("\n");
    LZ4_freeStream(stream);
    LZ4_freeStream(dict_stream);
    free(dict);
    free(out);
    free(safe);
}

static void do_hc(int level, int capacity, char *blocks) {
    LZ4_streamHC_t *state = LZ4_createStreamHC();
    unsigned char *out = malloc((size_t)capacity + 1);
    char *item;
    int first = 1;
    printf("ok");
    while ((item = next_item(&blocks)) != NULL) {
        size_t len;
        unsigned char *data = unhex(item, &len);
        int ret;
        fill_pattern(out, (size_t)capacity);
        if (first)
            ret = LZ4_compress_HC_extStateHC(state, (const char *)data, (char *)out, (int)len,
                                             capacity, level);
        else
            ret = LZ4_compress_HC_extStateHC_fastReset(state, (const char *)data, (char *)out,
                                                       (int)len, capacity, level);
        first = 0;
        printf(" %d/%016llx", ret, fnv64(out, (size_t)capacity));
        free(data);
    }
    printf("\n");
    LZ4_freeStreamHC(state);
    free(out);
}

static void do_hcdest(int level, int capacity, const char *data_hex) {
    size_t len;
    unsigned char *data = unhex(data_hex, &len);
    unsigned char *out = malloc((size_t)capacity + 1);
    LZ4_streamHC_t *state = LZ4_createStreamHC();
    int src_size = (int)len, ret;
    fill_pattern(out, (size_t)capacity);
    ret = LZ4_compress_HC_destSize(state, (const char *)data, (char *)out, &src_size, capacity,
                                   level);
    printf("%d %d %016llx\n", ret, src_size, fnv64(out, (size_t)capacity));
    LZ4_freeStreamHC(state);
    free(data);
    free(out);
}

static void do_hcstream(const char *dict_hex, const char *how, int level, int capacity,
                        char *blocks) {
    size_t dict_len;
    unsigned char *dict = unhex(dict_hex, &dict_len);
    LZ4_streamHC_t *stream = LZ4_createStreamHC();
    LZ4_streamHC_t *dict_stream = LZ4_createStreamHC();
    unsigned char *out = malloc((size_t)capacity + 1);
    char *safe = malloc(64 * 1024);
    char *item;
    LZ4_resetStreamHC(stream, level);
    if (how[0] == 'a') {
        LZ4_resetStreamHC(dict_stream, level);
        LZ4_loadDictHC(dict_stream, (const char *)dict, (int)dict_len);
        LZ4_resetStreamHC_fast(stream, level);
        LZ4_attach_HC_dictionary(stream, dict_stream);
    } else {
        if (how[0] == 'f')
            LZ4_favorDecompressionSpeed(stream, 1);
        LZ4_loadDictHC(stream, (const char *)dict, (int)dict_len);
    }
    printf("ok");
    while ((item = next_item(&blocks)) != NULL) {
        size_t len;
        unsigned char *data = unhex(item, &len);
        int ret;
        fill_pattern(out, (size_t)capacity);
        ret = LZ4_compress_HC_continue(stream, (const char *)data, (char *)out, (int)len,
                                       capacity);
        printf(" %d/%016llx", ret, fnv64(out, (size_t)capacity));
        LZ4_saveDictHC(stream, safe, 64 * 1024);
        free(data);
    }
    printf("\n");
    LZ4_freeStreamHC(stream);
    LZ4_freeStreamHC(dict_stream);
    free(dict);
    free(out);
    free(safe);
}

/* Preferences: "-" for none, else
 * level:blockSizeID:blockMode:contentChecksum:blockChecksum:contentSize:dictID:autoFlush:favorDecSpeed. */
static int parse_prefs(const char *text, LZ4F_preferences_t *prefs) {
    unsigned long long content_size;
    int level, bsid, mode, cchk, bchk, autoflush, favor;
    unsigned dict_id;
    memset(prefs, 0, sizeof(*prefs));
    if (strcmp(text, "-") == 0)
        return 0;
    sscanf(text, "%d:%d:%d:%d:%d:%llu:%u:%d:%d", &level, &bsid, &mode, &cchk, &bchk,
           &content_size, &dict_id, &autoflush, &favor);
    prefs->compressionLevel = level;
    prefs->frameInfo.blockSizeID = (LZ4F_blockSizeID_t)bsid;
    prefs->frameInfo.blockMode = (LZ4F_blockMode_t)mode;
    prefs->frameInfo.contentChecksumFlag = (LZ4F_contentChecksum_t)cchk;
    prefs->frameInfo.blockChecksumFlag = (LZ4F_blockChecksum_t)bchk;
    prefs->frameInfo.contentSize = content_size;
    prefs->frameInfo.dictID = dict_id;
    prefs->autoFlush = (unsigned)autoflush;
    prefs->favorDecSpeed = favor;
    return 1;
}

/* Frames compressed call by call: `steps`, comma-separated, are b<i> (begin
 * with preferences i, and the dictionary: `u` for _usingDict, `c` for
 * _usingCDict), u<n> (compressUpdate of the next n bytes), x<n>
 * (uncompressedUpdate), f (flush), e (end), F<i>.<n> (compressFrame) and
 * G<i>.<n> (compressFrame_usingCDict, with the same context), each with an
 * optional /<capacity> (else the bound). Prints what each returns, then the
 * size and hash of all the output. */
static void do_fcompress(char *prefs_list, const char *dict_kind, const char *dict_hex,
                         const char *steps, const char *data_hex) {
    size_t len, dict_len, consumed = 0, written = 0, room = 1 << 20;
    unsigned char *data = unhex(data_hex, &len);
    unsigned char *dict = unhex(dict_hex, &dict_len);
    unsigned char *out = malloc(room);
    LZ4F_preferences_t prefs[8];
    int has_prefs[8];
    int n_prefs = 0, current = -1;
    LZ4F_cctx *cctx;
    LZ4F_CDict *cdict = NULL;
    const char *p = steps;
    char *item, *save;
    for (item = strtok_r(prefs_list, ";", &save); item && n_prefs < 8;
         item = strtok_r(NULL, ";", &save)) {
        has_prefs[n_prefs] = parse_prefs(item, &prefs[n_prefs]);
        n_prefs++;
    }
    if (dict_kind[0] == 'c')
        cdict = LZ4F_createCDict(dict, dict_len);
    if (LZ4F_isError(LZ4F_createCompressionContext(&cctx, LZ4F_VERSION))) {
        printf("bad\n");
        return;
    }
    printf("ok");
    while (*p) {
        char kind = *p++;
        char *end;
        unsigned long arg = 0, n = 0;
        size_t take, capacity, ret;
        const LZ4F_preferences_t *pp = current >= 0 && has_prefs[current] ? &prefs[current] : NULL;
        unsigned char *dst;
        if (kind == 'b' || kind == 'u' || kind == 'x' || kind == 'F' || kind == 'G') {
            arg = strtoul(p, &end, 10);
            p = end;
        }
        if ((kind == 'F' || kind == 'G') && *p == '.') {
            n = strtoul(p + 1, &end, 10);
            p = end;
        }
        take = kind == 'u' || kind == 'x' ? arg : n;
        if (take > len - consumed)
            take = len - consumed;
        switch (kind) {
        case 'b':
            capacity = LZ4F_HEADER_SIZE_MAX;
            break;
        case 'u':
        case 'x':
            capacity = LZ4F_compressBound(take, pp);
            break;
        case 'F':
        case 'G':
            capacity = LZ4F_compressFrameBound(take, has_prefs[arg] ? &prefs[arg] : NULL);
            break;
        default:
            capacity = LZ4F_compressBound(0, pp);
        }
        if (*p == '/') {
            capacity = strtoul(p + 1, &end, 10);
            p = end;
        }
        dst = malloc(capacity + 1);
        switch (kind) {
        case 'b':
            current = (int)arg;
            pp = has_prefs[arg] ? &prefs[arg] : NULL;
            if (dict_kind[0] == 'u')
                ret = LZ4F_compressBegin_usingDict(cctx, dst, capacity, dict, dict_len, pp);
            else if (dict_kind[0] == 'c')
                ret = LZ4F_compressBegin_usingCDict(cctx, dst, capacity, cdict, pp);
            else
                ret = LZ4F_compressBegin(cctx, dst, capacity, pp);
            break;
        case 'u':
            ret = LZ4F_compressUpdate(cctx, dst, capacity, data + consumed, take, NULL);
            break;
        case 'x':
            ret = LZ4F_uncompressedUpdate(cctx, dst, capacity, data + consumed, take, NULL);
            break;
        case 'f':
            ret = LZ4F_flush(cctx, dst, capacity, NULL);
            break;
        case 'e':
            ret = LZ4F_compressEnd(cctx, dst, capacity, NULL);
            break;
        case 'F':
            ret = LZ4F_compressFrame(dst, capacity, data + consumed, take,
                                     has_prefs[arg] ? &prefs[arg] : NULL);
            break;
        default:
            ret = LZ4F_compressFrame_usingCDict(cctx, dst, capacity, data + consumed, take, cdict,
                                                has_prefs[arg] ? &prefs[arg] : NULL);
        }
        consumed += take;
        printf(" ");
        print_result(ret);
        if (!LZ4F_isError(ret)) {
            while (written + ret > room) {
                room *= 2;
                out = realloc(out, room);
            }
            memcpy(out + written, dst, ret);
            written += ret;
        }
        free(dst);
        if (LZ4F_isError(ret))
            break;
        if (*p == ',')
            p++;
    }
    printf(" %zu/%016llx\n", written, fnv64(out, written));
    LZ4F_freeCompressionContext(cctx);
    LZ4F_freeCDict(cdict);
    free(data);
    free(dict);
    free(out);
}

static void do_header(const char *data_hex) {
    size_t len;
    unsigned char *data = unhex(data_hex, &len);
    print_result(LZ4F_headerSize(data, len));
    printf("\n");
    free(data);
}

static void do_xxh32(unsigned seed, const char *pieces, const char *data_hex) {
    size_t len, at = 0;
    unsigned char *data = unhex(data_hex, &len);
    XXH32_state_t state;
    const char *p = pieces;
    XXH32_reset(&state, seed);
    while (*p && strcmp(pieces, "-") != 0) {
        char *end;
        unsigned long n = strtoul(p, &end, 10);
        size_t take = n < len - at ? n : len - at;
        XXH32_update(&state, data + at, take);
        at += take;
        p = end;
        if (*p == ',')
            p++;
    }
    XXH32_update(&state, data + at, len - at);
    printf("%08x %08x\n", XXH32(data, len, seed), XXH32_digest(&state));
    free(data);
}

int main(void) {
    while (fgets(line, sizeof(line), stdin)) {
        char *words[8];
        int n = 0;
        char *save, *word;
        line[strcspn(line, "\r\n")] = 0;
        for (word = strtok_r(line, " ", &save); word && n < 8; word = strtok_r(NULL, " ", &save))
            words[n++] = word;
        if (n == 6 && strcmp(words[0], "block") == 0)
            do_block(words[1], atoi(words[2]), atoi(words[3]), words[4], words[5]);
        else if (n == 4 && strcmp(words[0], "stream") == 0)
            do_stream(words[1], atoi(words[2]), words[3]);
        else if (n == 5 && strcmp(words[0], "frame") == 0)
            do_frame(words[1], atoi(words[2]), words[3], words[4]);
        else if (n == 4 && strcmp(words[0], "compress") == 0)
            do_compress(atoi(words[1]), atoi(words[2]), words[3]);
        else if (n == 4 && strcmp(words[0], "destsize") == 0)
            do_destsize(atoi(words[1]), atoi(words[2]), words[3]);
        else if (n == 6 && strcmp(words[0], "cstream") == 0)
            do_cstream(words[1], words[2], atoi(words[3]), atoi(words[4]), words[5]);
        else if (n == 4 && strcmp(words[0], "hc") == 0)
            do_hc(atoi(words[1]), atoi(words[2]), words[3]);
        else if (n == 4 && strcmp(words[0], "hcdest") == 0)
            do_hcdest(atoi(words[1]), atoi(words[2]), words[3]);
        else if (n == 6 && strcmp(words[0], "hcstream") == 0)
            do_hcstream(words[1], words[2], atoi(words[3]), atoi(words[4]), words[5]);
        else if (n == 6 && strcmp(words[0], "fcompress") == 0)
            do_fcompress(words[1], words[2], words[3], words[4], words[5]);
        else if (n == 2 && strcmp(words[0], "header") == 0)
            do_header(words[1]);
        else if (n == 4 && strcmp(words[0], "xxh32") == 0)
            do_xxh32((unsigned)strtoul(words[1], NULL, 10), words[2], words[3]);
        else
            printf("bad\n");
        fflush(stdout);
    }
    return 0;
}
