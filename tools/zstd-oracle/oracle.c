/*
 * The libzstd side of hivepack-zstd's comparison tests.
 *
 * It reads one request per line on stdin and answers each on one line of
 * stdout, by calling libzstd 1.5.7's internal functions directly. The Rust
 * tests ask the port the same questions and compare the answers as text.
 * scripts/testdata.py builds it from the zstd release sources.
 *
 * Byte strings are hexadecimal, lists are comma-separated, and "-" is an
 * empty list or byte string. A failure is answered "err <ZSTD_ErrorCode>".
 *
 *   ncount <maxSV> <hex>              FSE_readNCount
 *   fsedtable <maxSV> <tableLog> <counts>
 *                                     FSE_buildDTable_wksp
 *   fsedecompress <maxLog> <wkspSize> <dstCapacity> <hex>
 *                                     FSE_decompress_wksp_bmi2
 *   readstats <hex>                   HUF_readStats_wksp
 *   hufx1 <hex>, hufx2 <hex>          HUF_readDTableX1_wksp, HUF_readDTableX2_wksp
 *   bits <fast> <hex> <nbBits list>   BIT_initDStream, then BIT_readBits (or
 *                                     BIT_readBitsFast) and BIT_reloadDStream
 *   xxh64 <seed> <hex>                XXH64
 *   hufdec <table> <streams> <fast> <dstSize> <hex>
 *                                     Huffman decoding, as the decoder calls it: the table
 *                                     is "auto" (HUF_decompress1X_DCtx_wksp or
 *                                     HUF_decompress4X_hufOnly_wksp) or "x1"/"x2" (that
 *                                     table, then HUF_decompress{1,4}X_usingDTable);
 *                                     streams is 1 or 4; fast 0 sets HUF_flags_disableFast.
 *                                     HUF_flags_bmi2 is set when the processor has BMI2,
 *                                     as the decoder sets it.
 *   frames <maxBlockSize> <dstCapacity> <hex>
 *                                     ZSTD_decompressDCtx, on a new context with
 *                                     ZSTD_d_maxBlockSize set (0 for none), answered
 *                                     "ok <size> <FNV-1a of the output>"
 *
 * And two that make valid inputs for the others, from symbol counts:
 *   mkncount <tableLog> <counts>      FSE_normalizeCount, FSE_writeNCount
 *   mkhuf <maxNbBits> <counts>        HUF_buildCTable_wksp, HUF_writeCTable_wksp; maxNbBits
 *                                     must be at least HUF_minTableLog, as in libzstd
 *   blocks <dstCapacity> <blocks>    decodes compressed blocks one after the other into one
 *                                     output, with ZSTD_decompressBegin then
 *                                     ZSTD_decompressBlock for each "c<hex>" block and
 *                                     ZSTD_insertBlock for each stored "r<hex>" block
 *                                     (comma-separated); a failure is answered
 *                                     "err <code> <block index>", and a stored block that
 *                                     does not fit "short <block index>"
 *   mkblocks <level> <blockSize> <hex>
 *                                     <hex> compressed block by block with ZSTD_compressBegin
 *                                     and ZSTD_compressBlock, as the list "blocks" takes
 *   mkframe <level> <maxBlockSize> <hex>
 *                                     <hex> compressed with ZSTD_compress2, with a checksum
 *                                     and ZSTD_c_maxBlockSize set
 *   mkhufstream <streams> <maxNbBits> <hex>
 *                                     a Huffman table description followed by <hex>
 *                                     compressed with it (HUF_compress{1,4}X_usingCTable),
 *                                     or "none" when that is not possible
 *
 * Copyright (c) 2026 HivePaaS. MIT license.
 */

#define FSE_STATIC_LINKING_ONLY
#define HUF_STATIC_LINKING_ONLY
#define ZSTD_STATIC_LINKING_ONLY
#define ZSTD_DISABLE_DEPRECATE_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/bitstream.h"
#include "common/cpu.h"
#include "common/error_private.h"
#include "common/fse.h"
#include "common/huf.h"
#include "common/xxhash.h"
#include "compress/hist.h"
#include "zstd.h"

/* Large enough for every request the tests send. */
#define MAX_BYTES (1 << 20)

static unsigned char input[MAX_BYTES];
static unsigned char output[MAX_BYTES];

static int hex_value(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* Reads a hex string into `input`; returns its length, or -1. */
static long parse_hex(const char* text)
{
    size_t n = strlen(text), i;
    if (strcmp(text, "-") == 0) return 0;
    if (n % 2 || n / 2 > MAX_BYTES) return -1;
    for (i = 0; i < n / 2; i++) {
        int hi = hex_value(text[2 * i]), lo = hex_value(text[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        input[i] = (unsigned char)(hi * 16 + lo);
    }
    return (long)(n / 2);
}

static void print_hex(const unsigned char* bytes, size_t n)
{
    size_t i;
    if (n == 0) { fputs("-", stdout); return; }
    for (i = 0; i < n; i++) printf("%02x", bytes[i]);
}

/* Reads a list of up to `max` numbers; returns how many, or -1. */
static long parse_list(const char* text, long long* values, long max)
{
    long n = 0;
    const char* p = text;
    if (strcmp(text, "-") == 0) return 0;
    while (*p) {
        char* end;
        if (n == max) return -1;
        values[n++] = strtoll(p, &end, 10);
        if (end == p) return -1;
        p = end;
        if (*p == ',') p++;
        else if (*p) return -1;
    }
    return n;
}

static void answer_error(size_t code)
{
    printf("err %d\n", (int)ERR_getErrorCode(code));
}

static void ncount(char** args, int nargs)
{
    short counts[FSE_MAX_SYMBOL_VALUE + 1];
    unsigned maxSV, tableLog = 0, s;
    long n;
    size_t r;
    if (nargs != 2 || (n = parse_hex(args[1])) < 0) { puts("bad"); return; }
    maxSV = (unsigned)strtoul(args[0], NULL, 10);
    if (maxSV > FSE_MAX_SYMBOL_VALUE) { puts("bad"); return; }
    r = FSE_readNCount(counts, &maxSV, &tableLog, input, (size_t)n);
    if (FSE_isError(r)) { answer_error(r); return; }
    printf("ok %u %u %u ", (unsigned)r, maxSV, tableLog);
    for (s = 0; s <= maxSV; s++) printf(s ? ",%d" : "%d", counts[s]);
    puts("");
}

static void fsedtable(char** args, int nargs)
{
    long long values[FSE_MAX_SYMBOL_VALUE + 1];
    short counts[FSE_MAX_SYMBOL_VALUE + 1];
    FSE_DTable dt[FSE_DTABLE_SIZE_U32(FSE_MAX_TABLELOG)];
    unsigned wksp[FSE_BUILD_DTABLE_WKSP_SIZE_U32(FSE_MAX_TABLELOG, FSE_MAX_SYMBOL_VALUE)];
    unsigned maxSV, tableLog, u;
    long n, s;
    size_t r;
    if (nargs != 3) { puts("bad"); return; }
    maxSV = (unsigned)strtoul(args[0], NULL, 10);
    tableLog = (unsigned)strtoul(args[1], NULL, 10);
    n = parse_list(args[2], values, FSE_MAX_SYMBOL_VALUE + 1);
    if (n < 0 || maxSV > FSE_MAX_SYMBOL_VALUE || n != (long)maxSV + 1 || tableLog > FSE_MAX_TABLELOG) { puts("bad"); return; }
    for (s = 0; s < n; s++) counts[s] = (short)values[s];
    r = FSE_buildDTable_wksp(dt, counts, maxSV, tableLog, wksp, sizeof(wksp));
    if (FSE_isError(r)) { answer_error(r); return; }
    {   FSE_DTableHeader header;
        const FSE_decode_t* cells = (const FSE_decode_t*)(const void*)(dt + 1);
        memcpy(&header, dt, sizeof(header));
        printf("ok %u %u", header.tableLog, header.fastMode);
        for (u = 0; u < (1u << tableLog); u++)
            printf(" %u:%u:%u", cells[u].newState, cells[u].symbol, cells[u].nbBits);
        puts("");
    }
}

static void fsedecompress(char** args, int nargs)
{
    static unsigned wksp[FSE_DECOMPRESS_WKSP_SIZE_U32(FSE_MAX_TABLELOG, FSE_MAX_SYMBOL_VALUE)];
    unsigned maxLog;
    size_t wkspSize, dstCapacity, r;
    long n;
    if (nargs != 4 || (n = parse_hex(args[3])) < 0) { puts("bad"); return; }
    maxLog = (unsigned)strtoul(args[0], NULL, 10);
    wkspSize = strtoul(args[1], NULL, 10);
    dstCapacity = strtoul(args[2], NULL, 10);
    if (wkspSize > sizeof(wksp) || dstCapacity > MAX_BYTES || maxLog > FSE_MAX_TABLELOG) { puts("bad"); return; }
    r = FSE_decompress_wksp_bmi2(output, dstCapacity, input, (size_t)n, maxLog, wksp, wkspSize, 0);
    if (FSE_isError(r)) { answer_error(r); return; }
    printf("ok %u ", (unsigned)r);
    print_hex(output, r);
    puts("");
}

static void readstats(char** args, int nargs)
{
    BYTE weights[HUF_SYMBOLVALUE_MAX + 1];
    U32 rankStats[HUF_TABLELOG_MAX + 1];
    U32 wksp[HUF_READ_STATS_WORKSPACE_SIZE_U32];
    U32 nbSymbols = 0, tableLog = 0, s;
    long n;
    size_t r;
    if (nargs != 1 || (n = parse_hex(args[0])) < 0) { puts("bad"); return; }
    r = HUF_readStats_wksp(weights, sizeof(weights), rankStats, &nbSymbols, &tableLog,
                           input, (size_t)n, wksp, sizeof(wksp), 0);
    if (HUF_isError(r)) { answer_error(r); return; }
    printf("ok %u %u %u ", (unsigned)r, nbSymbols, tableLog);
    for (s = 0; s < nbSymbols; s++) printf(s ? ",%u" : "%u", weights[s]);
    putchar(' ');
    for (s = 0; s <= HUF_TABLELOG_MAX; s++) printf(s ? ",%u" : "%u", rankStats[s]);
    puts("");
}

static void hufdtable(char** args, int nargs, int x2)
{
    /* As the decoder sets up its table: ZSTD_HUFFDTABLE_CAPACITY_LOG is 12. */
    HUF_DTable dt[HUF_DTABLE_SIZE(12)] = { 12 * 0x1000001 };
    U32 wksp[HUF_DECOMPRESS_WORKSPACE_SIZE_U32];
    BYTE desc[4];
    long n;
    size_t r;
    unsigned u;
    if (nargs != 1 || (n = parse_hex(args[0])) < 0) { puts("bad"); return; }
    r = x2 ? HUF_readDTableX2_wksp(dt, input, (size_t)n, wksp, sizeof(wksp), 0)
           : HUF_readDTableX1_wksp(dt, input, (size_t)n, wksp, sizeof(wksp), 0);
    if (HUF_isError(r)) { answer_error(r); return; }
    memcpy(desc, dt, sizeof(desc));  /* maxTableLog, tableType, tableLog */
    printf("ok %u %u", (unsigned)r, desc[2]);
    for (u = 0; u < (1u << desc[2]); u++) {
        if (x2) {
            struct { U16 sequence; BYTE nbBits; BYTE length; } cell;
            memcpy(&cell, (const BYTE*)(dt + 1) + 4 * u, sizeof(cell));
            printf(" %u:%u:%u", cell.sequence, cell.nbBits, cell.length);
        } else {
            const BYTE* cell = (const BYTE*)(dt + 1) + 2 * u;  /* nbBits, byte */
            printf(" %u:%u", cell[0], cell[1]);
        }
    }
    puts("");
}

static void bits(char** args, int nargs)
{
    long long reads[4096];
    BIT_DStream_t bitD;
    long n, nreads, i;
    int fast;
    size_t r;
    if (nargs != 3 || (n = parse_hex(args[1])) < 0) { puts("bad"); return; }
    fast = atoi(args[0]);
    nreads = parse_list(args[2], reads, 4096);
    if (nreads < 0) { puts("bad"); return; }
    for (i = 0; i < nreads; i++) {
        if (reads[i] < (fast ? 1 : 0) || reads[i] > 31) { puts("bad"); return; }
    }
    r = BIT_initDStream(&bitD, input, (size_t)n);
    if (ERR_isError(r)) { answer_error(r); return; }
    printf("ok");
    for (i = 0; i < nreads; i++) {
        unsigned nb = (unsigned)reads[i];
        size_t value = fast ? BIT_readBitsFast(&bitD, nb) : BIT_readBits(&bitD, nb);
        BIT_DStream_status status = BIT_reloadDStream(&bitD);
        printf(" %zu/%d", value, (int)status);
    }
    printf(" end:%u\n", BIT_endOfDStream(&bitD));
}

static void xxh64(char** args, int nargs)
{
    long n;
    if (nargs != 2 || (n = parse_hex(args[1])) < 0) { puts("bad"); return; }
    printf("ok %016llx\n", (unsigned long long)XXH64(input, (size_t)n, strtoull(args[0], NULL, 10)));
}

static void mkncount(char** args, int nargs)
{
    long long values[FSE_MAX_SYMBOL_VALUE + 1];
    unsigned counts[FSE_MAX_SYMBOL_VALUE + 1];
    short normalized[FSE_MAX_SYMBOL_VALUE + 1];
    unsigned tableLog;
    size_t total = 0, r;
    long n, s;
    if (nargs != 2) { puts("bad"); return; }
    tableLog = (unsigned)strtoul(args[0], NULL, 10);
    n = parse_list(args[1], values, FSE_MAX_SYMBOL_VALUE + 1);
    if (n < 1) { puts("bad"); return; }
    for (s = 0; s < n; s++) { counts[s] = (unsigned)values[s]; total += counts[s]; }
    r = FSE_normalizeCount(normalized, tableLog, counts, total, (unsigned)n - 1, /* useLowProbCount */ total >= 2048);
    if (FSE_isError(r)) { answer_error(r); return; }
    r = FSE_writeNCount(output, MAX_BYTES, normalized, (unsigned)n - 1, tableLog);
    if (FSE_isError(r)) { answer_error(r); return; }
    printf("ok ");
    print_hex(output, r);
    puts("");
}

static void mkhuf(char** args, int nargs)
{
    long long values[HUF_SYMBOLVALUE_MAX + 1];
    unsigned counts[HUF_SYMBOLVALUE_MAX + 1];
    HUF_CElt table[HUF_CTABLE_SIZE_ST(HUF_SYMBOLVALUE_MAX)];
    static U64 wksp[HUF_WORKSPACE_SIZE_U64];
    unsigned maxNbBits;
    long n, s;
    size_t r, huffLog;
    if (nargs != 2) { puts("bad"); return; }
    maxNbBits = (unsigned)strtoul(args[0], NULL, 10);
    n = parse_list(args[1], values, HUF_SYMBOLVALUE_MAX + 1);
    if (n < 1) { puts("bad"); return; }
    for (s = 0; s < n; s++) counts[s] = (unsigned)values[s];
    /* libzstd's callers never ask for codes too short for the symbols. */
    if (maxNbBits < HUF_minTableLog(HUF_cardinality(counts, (unsigned)n - 1)) || maxNbBits > HUF_TABLELOG_MAX) {
        puts("bad");
        return;
    }
    memset(table, 0, sizeof(table));
    huffLog = HUF_buildCTable_wksp(table, counts, (unsigned)n - 1, maxNbBits, wksp, sizeof(wksp));
    if (HUF_isError(huffLog)) { answer_error(huffLog); return; }
    r = HUF_writeCTable_wksp(output, MAX_BYTES, table, (unsigned)n - 1, (unsigned)huffLog, wksp, sizeof(wksp));
    if (HUF_isError(r)) { answer_error(r); return; }
    printf("ok ");
    print_hex(output, r);
    puts("");
}

static void hufdec(char** args, int nargs)
{
    HUF_DTable dt[HUF_DTABLE_SIZE(12)] = { 12 * 0x1000001 };
    static U32 wksp[HUF_DECOMPRESS_WORKSPACE_SIZE_U32];
    int streams, flags;
    size_t dstSize, r;
    long n;
    if (nargs != 5 || (n = parse_hex(args[4])) < 0) { puts("bad"); return; }
    streams = atoi(args[1]);
    dstSize = strtoul(args[3], NULL, 10);
    if ((streams != 1 && streams != 4) || dstSize > MAX_BYTES) { puts("bad"); return; }
    flags = (ZSTD_cpuid_bmi2(ZSTD_cpuid()) ? HUF_flags_bmi2 : 0) | (atoi(args[2]) ? 0 : HUF_flags_disableFast);
    if (!strcmp(args[0], "auto")) {
        r = streams == 1
            ? HUF_decompress1X_DCtx_wksp(dt, output, dstSize, input, (size_t)n, wksp, sizeof(wksp), flags)
            : HUF_decompress4X_hufOnly_wksp(dt, output, dstSize, input, (size_t)n, wksp, sizeof(wksp), flags);
    } else {
        size_t const h = !strcmp(args[0], "x2")
            ? HUF_readDTableX2_wksp(dt, input, (size_t)n, wksp, sizeof(wksp), flags)
            : HUF_readDTableX1_wksp(dt, input, (size_t)n, wksp, sizeof(wksp), flags);
        if (HUF_isError(h)) { answer_error(h); return; }
        if (h >= (size_t)n) { answer_error(ERROR(srcSize_wrong)); return; }
        r = streams == 1
            ? HUF_decompress1X_usingDTable(output, dstSize, input + h, (size_t)n - h, dt, flags)
            : HUF_decompress4X_usingDTable(output, dstSize, input + h, (size_t)n - h, dt, flags);
    }
    if (HUF_isError(r)) { answer_error(r); return; }
    printf("ok %u ", (unsigned)r);
    print_hex(output, r);
    puts("");
}

static void mkhufstream(char** args, int nargs)
{
    unsigned counts[HUF_SYMBOLVALUE_MAX + 1];
    HUF_CElt table[HUF_CTABLE_SIZE_ST(HUF_SYMBOLVALUE_MAX)];
    static U64 wksp[HUF_WORKSPACE_SIZE_U64];
    unsigned maxSV = HUF_SYMBOLVALUE_MAX, maxNbBits;
    int streams;
    size_t hSize, cSize, huffLog;
    long n;
    if (nargs != 3 || (n = parse_hex(args[2])) < 0) { puts("bad"); return; }
    streams = atoi(args[0]);
    maxNbBits = (unsigned)strtoul(args[1], NULL, 10);
    if ((streams != 1 && streams != 4) || n == 0) { puts("bad"); return; }
    HIST_count_simple(counts, &maxSV, input, (size_t)n);
    if (HUF_cardinality(counts, maxSV) < 2) { puts("none"); return; }
    if (maxNbBits < HUF_minTableLog(HUF_cardinality(counts, maxSV)) || maxNbBits > HUF_TABLELOG_MAX) { puts("bad"); return; }
    memset(table, 0, sizeof(table));
    huffLog = HUF_buildCTable_wksp(table, counts, maxSV, maxNbBits, wksp, sizeof(wksp));
    if (HUF_isError(huffLog)) { answer_error(huffLog); return; }
    hSize = HUF_writeCTable_wksp(output, MAX_BYTES, table, maxSV, (unsigned)huffLog, wksp, sizeof(wksp));
    if (HUF_isError(hSize)) { answer_error(hSize); return; }
    cSize = streams == 1
        ? HUF_compress1X_usingCTable(output + hSize, MAX_BYTES - hSize, input, (size_t)n, table, 0)
        : HUF_compress4X_usingCTable(output + hSize, MAX_BYTES - hSize, input, (size_t)n, table, 0);
    if (HUF_isError(cSize)) { answer_error(cSize); return; }
    if (cSize == 0) { puts("none"); return; }
    printf("ok ");
    print_hex(output, hSize + cSize);
    puts("");
}

/* An output line of any length. */
static char* line_out;
static size_t line_len, line_cap;

static void line_reset(void) { line_len = 0; }

static void line_append(const char* text, size_t n)
{
    if (line_len + n + 1 > line_cap) {
        line_cap = (line_len + n + 1) * 2;
        line_out = (char*)realloc(line_out, line_cap);
        if (!line_out) { puts("bad"); exit(1); }
    }
    memcpy(line_out + line_len, text, n);
    line_len += n;
    line_out[line_len] = 0;
}

static void line_append_hex(const unsigned char* bytes, size_t n)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        char pair[2];
        pair[0] = digits[bytes[i] >> 4];
        pair[1] = digits[bytes[i] & 15];
        line_append(pair, 2);
    }
}

static void mkblocks(char** args, int nargs)
{
    static ZSTD_CCtx* cctx;
    size_t blockSize, pos, r;
    long n;
    if (nargs != 3 || (n = parse_hex(args[2])) < 0) { puts("bad"); return; }
    if (!cctx) cctx = ZSTD_createCCtx();
    blockSize = strtoul(args[1], NULL, 10);
    if (blockSize == 0 || blockSize > ZSTD_BLOCKSIZE_MAX) { puts("bad"); return; }
    r = ZSTD_compressBegin(cctx, atoi(args[0]));
    if (ZSTD_isError(r)) { answer_error(r); return; }
    if (blockSize > ZSTD_getBlockSize(cctx)) blockSize = ZSTD_getBlockSize(cctx);
    line_reset();
    line_append("ok ", 3);
    for (pos = 0; pos < (size_t)n; pos += blockSize) {
        size_t const chunk = (size_t)n - pos < blockSize ? (size_t)n - pos : blockSize;
        size_t const c = ZSTD_compressBlock(cctx, output, MAX_BYTES, input + pos, chunk);
        if (ZSTD_isError(c)) { answer_error(c); return; }
        if (pos) line_append(",", 1);
        if (c == 0) { line_append("r", 1); line_append_hex(input + pos, chunk); }
        else { line_append("c", 1); line_append_hex(output, c); }
    }
    puts(line_out);
}

static void blocks(char** args, int nargs)
{
    static ZSTD_DCtx* dctx;
    size_t cap, pos = 0;
    char* item;
    int index = 0;
    if (nargs != 2) { puts("bad"); return; }
    if (!dctx) dctx = ZSTD_createDCtx();
    cap = strtoul(args[0], NULL, 10);
    if (cap > MAX_BYTES) { puts("bad"); return; }
    ZSTD_decompressBegin(dctx);
    for (item = args[1]; item && *item; index++) {
        char* const next = strchr(item, ',');
        long n;
        if (next) *next = 0;
        n = parse_hex(item + 1);
        if (n < 0) { puts("bad"); return; }
        if (item[0] == 'c') {
            size_t const r = ZSTD_decompressBlock(dctx, output + pos, cap - pos, input, (size_t)n);
            if (ZSTD_isError(r)) { printf("err %d %d\n", (int)ERR_getErrorCode(r), index); return; }
            pos += r;
        } else {
            if ((size_t)n > cap - pos) { printf("short %d\n", index); return; }
            memcpy(output + pos, input, (size_t)n);
            ZSTD_insertBlock(dctx, output + pos, (size_t)n);
            pos += (size_t)n;
        }
        item = next ? next + 1 : NULL;
    }
    line_reset();
    {   char head[64];
        int const k = snprintf(head, sizeof(head), "ok %u ", (unsigned)pos);
        line_append(head, (size_t)k);
    }
    if (pos == 0) line_append("-", 1);
    line_append_hex(output, pos);
    puts(line_out);
}

/* FNV-1a, 64 bits. */
static unsigned long long fnv64(const unsigned char* bytes, size_t n)
{
    unsigned long long hash = 0xcbf29ce484222325ULL;
    size_t i;
    for (i = 0; i < n; i++) {
        hash ^= bytes[i];
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

static void mkframe(char** args, int nargs)
{
    static ZSTD_CCtx* cctx;
    size_t r;
    long n;
    if (nargs != 3 || (n = parse_hex(args[2])) < 0) { puts("bad"); return; }
    if (!cctx) cctx = ZSTD_createCCtx();
    ZSTD_CCtx_reset(cctx, ZSTD_reset_session_and_parameters);
    r = ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, atoi(args[0]));
    if (!ZSTD_isError(r)) r = ZSTD_CCtx_setParameter(cctx, ZSTD_c_maxBlockSize, atoi(args[1]));
    if (!ZSTD_isError(r)) r = ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, 1);
    if (!ZSTD_isError(r)) r = ZSTD_compress2(cctx, output, MAX_BYTES, input, (size_t)n);
    if (ZSTD_isError(r)) { answer_error(r); return; }
    line_reset();
    line_append("ok ", 3);
    line_append_hex(output, r);
    puts(line_out);
}

static void frames(char** args, int nargs)
{
    ZSTD_DCtx* dctx;
    size_t cap, r;
    long n;
    if (nargs != 3 || (n = parse_hex(args[2])) < 0) { puts("bad"); return; }
    cap = strtoul(args[1], NULL, 10);
    if (cap > MAX_BYTES) { puts("bad"); return; }
    dctx = ZSTD_createDCtx();
    r = ZSTD_DCtx_setParameter(dctx, ZSTD_d_maxBlockSize, atoi(args[0]));
    if (!ZSTD_isError(r)) r = ZSTD_decompressDCtx(dctx, output, cap, input, (size_t)n);
    ZSTD_freeDCtx(dctx);
    if (ZSTD_isError(r)) { answer_error(r); return; }
    printf("ok %u %016llx\n", (unsigned)r, fnv64(output, r));
}

int main(void)
{
    static char line[4 * MAX_BYTES];
    while (fgets(line, sizeof(line), stdin)) {
        char* args[8];
        int nargs = 0;
        char* command = strtok(line, " \n");
        char* arg;
        if (!command) continue;
        while (nargs < 8 && (arg = strtok(NULL, " \n"))) args[nargs++] = arg;
        if      (!strcmp(command, "ncount")) ncount(args, nargs);
        else if (!strcmp(command, "fsedtable")) fsedtable(args, nargs);
        else if (!strcmp(command, "fsedecompress")) fsedecompress(args, nargs);
        else if (!strcmp(command, "readstats")) readstats(args, nargs);
        else if (!strcmp(command, "hufx1")) hufdtable(args, nargs, 0);
        else if (!strcmp(command, "hufx2")) hufdtable(args, nargs, 1);
        else if (!strcmp(command, "bits")) bits(args, nargs);
        else if (!strcmp(command, "xxh64")) xxh64(args, nargs);
        else if (!strcmp(command, "mkncount")) mkncount(args, nargs);
        else if (!strcmp(command, "mkhuf")) mkhuf(args, nargs);
        else if (!strcmp(command, "hufdec")) hufdec(args, nargs);
        else if (!strcmp(command, "mkhufstream")) mkhufstream(args, nargs);
        else if (!strcmp(command, "mkblocks")) mkblocks(args, nargs);
        else if (!strcmp(command, "blocks")) blocks(args, nargs);
        else if (!strcmp(command, "mkframe")) mkframe(args, nargs);
        else if (!strcmp(command, "frames")) frames(args, nargs);
        else puts("bad");
        fflush(stdout);
    }
    return 0;
}
