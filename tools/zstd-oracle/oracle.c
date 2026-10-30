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
 *   stream <maxBlockSize> <stable> <windowLogMax> <dstCapacity> <steps> <hex>
 *                                     ZSTD_decompressStream, called once per pair of
 *                                     <steps> on a new context with ZSTD_d_maxBlockSize,
 *                                     ZSTD_d_stableOutBuffer and ZSTD_d_windowLogMax set:
 *                                     before each call the input ends the pair's first
 *                                     number past its position, and the output the second
 *                                     (all of it when stable). It goes on after errors.
 *                                     Answered "ok", then "<result>/<input pos>/<output
 *                                     pos>" for each call, where a failure is "e<code>",
 *                                     then the FNV-1a of the output
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
 * The encoder's entropy coding. Tables are answered whole, with the cells a
 * function leaves alone still holding the filler they started with
 * (0xdeadbeef words, 0x7777 counts, 0xaaaaaaaa histogram counts), so that
 * the port must write exactly the same cells:
 *   hist <mode> <maxSV> <hex>         HIST_count_simple ("simple"), HIST_countFast_wksp
 *                                     ("fast"), or HIST_count_wksp ("wksp"), answered
 *                                     "ok <largest> <maxSV> <256 counts>"
 *   fseoptlog <maxTableLog> <srcSize> <maxSV> <minus>
 *                                     FSE_optimalTableLog_internal
 *   fsenorm <tableLog> <useLowProbCount> <counts>
 *                                     FSE_normalizeCount, of counts summing to at least 2
 *   fsencount <bufferSize> <maxSV> <tableLog> <normalized>
 *                                     FSE_writeNCount
 *   fsectable <maxSV> <tableLog> <normalized>
 *                                     FSE_buildCTable_wksp, of a valid distribution: the
 *                                     table's words, then FSE_bitCost (accuracy 8) and
 *                                     FSE_getMaxNbBits of each symbol
 *   fsectablerle <symbol>             FSE_buildCTable_rle
 *   fsecompress <maxTableLog> <useLowProbCount> <dstCapacity> <hex>
 *                                     HIST_count_simple, FSE_optimalTableLog,
 *                                     FSE_normalizeCount and FSE_buildCTable_wksp, then
 *                                     FSE_compress_usingCTable; "none" for a single symbol
 *   bitc <dstCapacity> <ops>          BIT_initCStream, then for each triple of <ops>
 *                                     (value, nbBits, how) BIT_addBits (how 0), BIT_addBits
 *                                     and BIT_flushBits (1) or BIT_addBitsFast and
 *                                     BIT_flushBits (2), then BIT_closeCStream
 *   hufctable <maxNbBits> <counts>    HUF_buildCTable_wksp: the table as little-endian
 *                                     words, then HUF_writeCTable_wksp
 *   hufoptlog <maxTableLog> <flags> <counts>
 *                                     HUF_optimalTableLog
 *   hufcompress <streams> <maxSV> <huffLog> <flags> <dstCapacity> <repeat> <table> <hex>
 *                                     HUF_compress{1,4}X_repeat, with the previous table
 *                                     given as little-endian words, the ones left out
 *                                     being filler ("-": none, and no repeat mode
 *                                     either), answered "ok <result> <repeat> <output>
 *                                     <table>". The table is answered up to its largest
 *                                     symbol: libzstd copies a new table whole from its
 *                                     workspace, past that symbol too, but never reads
 *                                     those cells.
 *   hufreadctable <maxSV> <hex>       HUF_readCTable, answered "ok <size> <maxSV>
 *                                     <hasZeroWeights> <table>"
 *
 * Frames:
 *   compress <level> <dstCapacity> <hex>
 *                                     ZSTD_compressCCtx, on one context used again and again
 *   zstdmt                            whether the oracle is built with libzstd's threads
 *                                     (ZSTD_MULTITHREAD), for the cstream requests that
 *                                     set ZSTD_c_nbWorkers: answered "1" or "0"
 *
 * A block's entropy coding, with the tables of the block before kept from
 * request to request, as the block compressor keeps them:
 *   seqreset                          new tables: every word filler, none to be used again
 *   seqblock <strategy> <literalMode> <targetLength> <dstCapacity> <literals> <sequences>
 *                                     ZSTD_entropyCompressSeqStore of the literals and the
 *                                     sequences, triples (offBase, litLength, matchLength),
 *                                     at most one length over 0xFFFF (+ MINMATCH for a match);
 *                                     the block size is the literals plus the match lengths.
 *                                     As ZSTD_compressBlock_internal does, a block that
 *                                     compresses (more than 1 byte) makes its tables the
 *                                     previous ones. Answered "ok <size> <output> <repeat
 *                                     modes: huf,of,ml,ll> <FNV-1a of the tables>", the
 *                                     Huffman table up to its largest symbol (see
 *                                     hufcompress)
 *
 * The dictionary builder (lib/dictBuilder), on samples given as their sizes
 * <sizes> and their bytes one after the other <hex>, its dictionaries
 * answered "ok <hex>". Its parameters are lists: <zparams> is
 * compressionLevel,notificationLevel,dictID (ZDICT_params_t); <cover> is
 * k,d,steps,nbThreads,splitPoint,shrinkDict,shrinkDictMaxRegression and
 * <zparams> (ZDICT_cover_params_t); <fastcover> is
 * k,d,f,steps,nbThreads,splitPoint,accel,shrinkDict,shrinkDictMaxRegression
 * and <zparams> (ZDICT_fastCover_params_t). Given, splitPoint is in
 * thousandths; answered, it is the bits of the double, in hex:
 *   zdcover <capacity> <cover> <sizes> <hex>
 *                                     ZDICT_trainFromBuffer_cover
 *   zdcoveropt <capacity> <cover> <sizes> <hex>
 *                                     ZDICT_optimizeTrainFromBuffer_cover, answered
 *                                     "ok <hex> <cover>" with the parameters it chose
 *   zdfast <capacity> <fastcover> <sizes> <hex>
 *                                     ZDICT_trainFromBuffer_fastCover
 *   zdfastopt <capacity> <fastcover> <sizes> <hex>
 *                                     ZDICT_optimizeTrainFromBuffer_fastCover, answered
 *                                     "ok <hex> <fastcover>"
 *   zdfinalize <capacity> <zparams> <content> <sizes> <hex>
 *                                     ZDICT_finalizeDictionary, the content in a buffer of
 *                                     its own
 *   zdadd <contentSize> <zparams> <buffer> <sizes> <hex>
 *                                     ZDICT_addEntropyTablesFromBuffer_advanced, on a copy
 *                                     of <buffer>, whose last <contentSize> bytes are the
 *                                     content
 *   zdentropy <dstCapacity> <level> <content> <sizes> <hex>
 *                                     ZDICT_analyzeEntropy, answered "ok <tables>"
 *   zdselect <capacity> <cover> <content> <nbFinalize> <nbCheck> <sizes> <hex>
 *                                     COVER_selectDict, with the content at the end of a
 *                                     buffer of <capacity> bytes, zeros before it, answered
 *                                     "ok <totalCompressedSize> <hex>"
 *   zdheader <hex>                    ZDICT_getDictHeaderSize, answered "ok <size>"
 *   zdepochs <maxDictSize> <nbDmers> <k> <passes>
 *                                     COVER_computeEpochs, answered "ok <num> <size>"
 * cover.c sorts its suffix array with the C library's qsort_r, breaking ties
 * by the elements' addresses: only a stable sort, as glibc's merge sort is,
 * gives the order cover.c counts on. On macOS the oracle has a qsort_r of its
 * own, glibc's merge sort, so that its answers are libzstd's on Linux.
 *
 * Copyright (c) 2026 HivePaaS. MIT license.
 */

#define FSE_STATIC_LINKING_ONLY
#define HUF_STATIC_LINKING_ONLY
#define ZSTD_STATIC_LINKING_ONLY
#define ZSTD_DISABLE_DEPRECATE_WARNINGS

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/bitstream.h"
#include "common/cpu.h"
#include "common/error_private.h"
#include "common/fse.h"
#include "common/huf.h"
#include "common/xxhash.h"
#include "compress/hist.h"
#include "zstd.h"
/* Included rather than linked (scripts/testdata.py leaves it out), to reach
 * its static functions: ZSTD_entropyCompressSeqStore. */
#include "compress/zstd_compress.c"
/* The same for the dictionary builder's ZDICT_analyzeEntropy and
 * ZDICT_addEntropyTablesFromBuffer_advanced; cover.c and fastcover.c are
 * linked. */
#include "dictBuilder/zdict.c"
#include "dictBuilder/cover.h"

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

/* Reads a hex string into `bytes`, of MAX_BYTES; returns its length, or -1. */
static long parse_hex_into(const char* text, unsigned char* bytes)
{
    size_t n = strlen(text), i;
    if (strcmp(text, "-") == 0) return 0;
    if (n % 2 || n / 2 > MAX_BYTES) return -1;
    for (i = 0; i < n / 2; i++) {
        int hi = hex_value(text[2 * i]), lo = hex_value(text[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        bytes[i] = (unsigned char)(hi * 16 + lo);
    }
    return (long)(n / 2);
}

/* Reads a hex string into `input`; returns its length, or -1. */
static long parse_hex(const char* text)
{
    return parse_hex_into(text, input);
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

/* ---- The encoder's entropy coding ---- */

#define FILLER_WORD 0xdeadbeefu
#define FILLER_NORM ((short)0x7777)
#define FILLER_COUNT 0xaaaaaaaau

/* The workspace every entropy function below gets: as much as libzstd's
 * Huffman functions take, and for FSE tables enough for the largest. */
static U64 entropy_wksp[HUF_WORKSPACE_SIZE_U64];
static unsigned fse_wksp[FSE_BUILD_CTABLE_WORKSPACE_SIZE_U32(FSE_MAX_SYMBOL_VALUE, FSE_MAX_TABLELOG)];

static int parse_counts(const char* text, unsigned* counts, long max, long* n)
{
    static long long values[256];
    long s;
    *n = parse_list(text, values, max);
    if (*n < 1) return 0;
    for (s = 0; s < *n; s++) {
        if (values[s] < 0 || values[s] > 0xffffffffLL) return 0;
        counts[s] = (unsigned)values[s];
    }
    return 1;
}

static void hist(char** args, int nargs)
{
    unsigned count[256];
    unsigned maxSV, s;
    long n, i;
    size_t r;
    if (nargs != 3 || (n = parse_hex(args[2])) < 0) { puts("bad"); return; }
    maxSV = (unsigned)strtoul(args[1], NULL, 10);
    if (maxSV > 255) { puts("bad"); return; }
    for (s = 0; s < 256; s++) count[s] = FILLER_COUNT;
    if (!strcmp(args[0], "wksp")) {
        r = HIST_count_wksp(count, &maxSV, input, (size_t)n, entropy_wksp, sizeof(entropy_wksp));
    } else {
        /* These two trust the input to stay within maxSV. */
        for (i = 0; i < n; i++) if (input[i] > maxSV) { puts("bad"); return; }
        r = !strcmp(args[0], "simple")
            ? HIST_count_simple(count, &maxSV, input, (size_t)n)
            : HIST_countFast_wksp(count, &maxSV, input, (size_t)n, entropy_wksp, sizeof(entropy_wksp));
    }
    if (HIST_isError(r)) { answer_error(r); return; }
    printf("ok %u %u ", (unsigned)r, maxSV);
    for (s = 0; s < 256; s++) printf(s ? ",%u" : "%u", count[s]);
    puts("");
}

static void fseoptlog(char** args, int nargs)
{
    size_t srcSize;
    if (nargs != 4) { puts("bad"); return; }
    srcSize = strtoul(args[1], NULL, 10);
    if (srcSize < 2) { puts("bad"); return; }
    printf("ok %u\n", FSE_optimalTableLog_internal((unsigned)strtoul(args[0], NULL, 10), srcSize,
        (unsigned)strtoul(args[2], NULL, 10), (unsigned)strtoul(args[3], NULL, 10)));
}

static void fsenorm(char** args, int nargs)
{
    unsigned counts[256];
    short norm[256];
    size_t total = 0, r;
    long n, s;
    if (nargs != 3 || !parse_counts(args[2], counts, 256, &n)) { puts("bad"); return; }
    for (s = 0; s < n; s++) total += counts[s];
    if (total < 2) { puts("bad"); return; }
    for (s = 0; s < 256; s++) norm[s] = FILLER_NORM;
    r = FSE_normalizeCount(norm, (unsigned)strtoul(args[0], NULL, 10), counts, total,
                           (unsigned)n - 1, (unsigned)atoi(args[1]));
    if (FSE_isError(r)) { answer_error(r); return; }
    printf("ok %u ", (unsigned)r);
    for (s = 0; s < n; s++) printf(s ? ",%d" : "%d", norm[s]);
    puts("");
}

static int parse_norm(const char* text, short* norm, long* n)
{
    static long long values[256];
    long s;
    *n = parse_list(text, values, 256);
    if (*n < 1) return 0;
    for (s = 0; s < *n; s++) {
        if (values[s] < -32768 || values[s] > 32767) return 0;
        norm[s] = (short)values[s];
    }
    return 1;
}

static void fsencount(char** args, int nargs)
{
    short norm[256];
    size_t bufferSize, r;
    long n;
    if (nargs != 4 || !parse_norm(args[3], norm, &n)) { puts("bad"); return; }
    bufferSize = strtoul(args[0], NULL, 10);
    if (bufferSize > MAX_BYTES || n != (long)strtoul(args[1], NULL, 10) + 1) { puts("bad"); return; }
    r = FSE_writeNCount(output, bufferSize, norm, (unsigned)n - 1, (unsigned)strtoul(args[2], NULL, 10));
    if (FSE_isError(r)) { answer_error(r); return; }
    printf("ok ");
    print_hex(output, r);
    puts("");
}

static void fsectable(char** args, int nargs)
{
    FSE_CTable ct[FSE_CTABLE_SIZE_U32(FSE_MAX_TABLELOG, FSE_MAX_SYMBOL_VALUE)];
    short norm[256];
    unsigned maxSV, tableLog, words, s;
    long n;
    size_t r;
    if (nargs != 3 || !parse_norm(args[2], norm, &n)) { puts("bad"); return; }
    maxSV = (unsigned)strtoul(args[0], NULL, 10);
    tableLog = (unsigned)strtoul(args[1], NULL, 10);
    if (n != (long)maxSV + 1 || tableLog < FSE_MIN_TABLELOG || tableLog > FSE_MAX_TABLELOG) { puts("bad"); return; }
    {   /* Only valid distributions: libzstd builds tables from FSE_normalizeCount. */
        long total = 0;
        for (s = 0; s <= maxSV; s++) {
            if (norm[s] < -1) { puts("bad"); return; }
            total += norm[s] < 0 ? 1 : norm[s];
        }
        if (total != (1L << tableLog)) { puts("bad"); return; }
    }
    words = FSE_CTABLE_SIZE_U32(tableLog, maxSV);
    for (s = 0; s < words; s++) ct[s] = FILLER_WORD;
    r = FSE_buildCTable_wksp(ct, norm, maxSV, tableLog, fse_wksp, sizeof(fse_wksp));
    if (FSE_isError(r)) { answer_error(r); return; }
    printf("ok ");
    for (s = 0; s < words; s++) printf(s ? ",%u" : "%u", ct[s]);
    {   FSE_CState_t cstate;
        FSE_initCState(&cstate, ct);
        putchar(' ');
        for (s = 0; s <= maxSV; s++) printf(s ? ",%u" : "%u", FSE_bitCost(cstate.symbolTT, tableLog, s, 8));
        putchar(' ');
        for (s = 0; s <= maxSV; s++) printf(s ? ",%u" : "%u", FSE_getMaxNbBits(cstate.symbolTT, s));
    }
    puts("");
}

static void fsectablerle(char** args, int nargs)
{
    FSE_CTable ct[2 + 2 * 256];
    unsigned symbol, s;
    if (nargs != 1) { puts("bad"); return; }
    symbol = (unsigned)strtoul(args[0], NULL, 10);
    if (symbol > 255) { puts("bad"); return; }
    for (s = 0; s < 2 + 2 * (symbol + 1); s++) ct[s] = FILLER_WORD;
    FSE_buildCTable_rle(ct, (BYTE)symbol);
    printf("ok ");
    for (s = 0; s < 2 + 2 * (symbol + 1); s++) printf(s ? ",%u" : "%u", ct[s]);
    puts("");
}

static void fsecompress(char** args, int nargs)
{
    FSE_CTable ct[FSE_CTABLE_SIZE_U32(FSE_MAX_TABLELOG, FSE_MAX_SYMBOL_VALUE)];
    unsigned counts[256];
    short norm[256];
    unsigned maxSV = 255, tableLog, largest;
    size_t dstCapacity, r;
    long n;
    if (nargs != 4 || (n = parse_hex(args[3])) < 0) { puts("bad"); return; }
    dstCapacity = strtoul(args[2], NULL, 10);
    if (dstCapacity > MAX_BYTES) { puts("bad"); return; }
    largest = HIST_count_simple(counts, &maxSV, input, (size_t)n);
    if (n < 2 || largest == (unsigned)n) { puts("none"); return; }
    tableLog = FSE_optimalTableLog((unsigned)strtoul(args[0], NULL, 10), (size_t)n, maxSV);
    r = FSE_normalizeCount(norm, tableLog, counts, (size_t)n, maxSV, (unsigned)atoi(args[1]));
    if (FSE_isError(r)) { answer_error(r); return; }
    r = FSE_buildCTable_wksp(ct, norm, maxSV, tableLog, fse_wksp, sizeof(fse_wksp));
    if (FSE_isError(r)) { answer_error(r); return; }
    r = FSE_compress_usingCTable(output, dstCapacity, input, (size_t)n, ct);
    if (FSE_isError(r)) { answer_error(r); return; }
    printf("ok %u %u ", tableLog, (unsigned)r);
    print_hex(output, r);
    puts("");
}

static void bitc(char** args, int nargs)
{
    static long long ops[3 * 4096];
    BIT_CStream_t bitC;
    size_t dstCapacity, r;
    long nops, i;
    if (nargs != 2) { puts("bad"); return; }
    dstCapacity = strtoul(args[0], NULL, 10);
    nops = parse_list(args[1], ops, 3 * 4096);
    if (dstCapacity > MAX_BYTES || nops < 0 || nops % 3) { puts("bad"); return; }
    r = BIT_initCStream(&bitC, output, dstCapacity);
    if (ERR_isError(r)) { answer_error(r); return; }
    for (i = 0; i < nops; i += 3) {
        unsigned const nbBits = (unsigned)ops[i + 1];
        /* The register must not overflow: the requests flush in time. */
        if (ops[i] < 0 || nbBits > 31 || bitC.bitPos + nbBits >= 64) { puts("bad"); return; }
        if (ops[i + 2] == 2) {
            if (nbBits < 63 && ((unsigned long long)ops[i] >> nbBits) != 0) { puts("bad"); return; }
            BIT_addBitsFast(&bitC, (size_t)ops[i], nbBits);
        } else {
            BIT_addBits(&bitC, (size_t)ops[i], nbBits);
        }
        if (ops[i + 2]) BIT_flushBits(&bitC);
    }
    if (bitC.bitPos >= 63) { puts("bad"); return; }
    r = BIT_closeCStream(&bitC);
    printf("ok %u ", (unsigned)r);
    print_hex(output, r);
    puts("");
}

static void print_words_le(const HUF_CElt* table, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned char bytes[8];
        unsigned long long const v = table[i];
        int b;
        for (b = 0; b < 8; b++) bytes[b] = (unsigned char)(v >> (8 * b));
        print_hex(bytes, 8);
    }
}

static void line_append_words_le(const HUF_CElt* table, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned char bytes[8];
        unsigned long long const v = table[i];
        int b;
        for (b = 0; b < 8; b++) bytes[b] = (unsigned char)(v >> (8 * b));
        line_append_hex(bytes, 8);
    }
}

/* Reads up to `n` little-endian words from hex, the rest being filler;
 * returns 1, or 0 when the length is wrong. */
static int parse_words_le(const char* text, HUF_CElt* table, size_t n)
{
    size_t i, len = strlen(text);
    if (len % 16 || len > 16 * n) return 0;
    for (i = len / 16; i < n; i++) table[i] = ((HUF_CElt)FILLER_WORD << 32) | FILLER_WORD;
    for (i = 0; i < len / 16; i++) {
        unsigned long long v = 0;
        int b;
        for (b = 7; b >= 0; b--) {
            int const hi = hex_value(text[16 * i + 2 * b]), lo = hex_value(text[16 * i + 2 * b + 1]);
            if (hi < 0 || lo < 0) return 0;
            v = (v << 8) | (unsigned)(hi * 16 + lo);
        }
        table[i] = (HUF_CElt)v;
    }
    return 1;
}

/* Counts libzstd's Huffman builders accept: two symbols or more, and room for them. */
static int huf_counts_ok(const unsigned* counts, unsigned maxSV, unsigned maxNbBits)
{
    unsigned const cardinality = HUF_cardinality(counts, maxSV);
    return cardinality >= 2 && maxNbBits >= HUF_minTableLog(cardinality) && maxNbBits <= HUF_TABLELOG_MAX;
}

static void hufctable(char** args, int nargs)
{
    HUF_CElt table[HUF_CTABLE_SIZE_ST(HUF_SYMBOLVALUE_MAX)];
    unsigned counts[256];
    unsigned maxNbBits, s;
    long n;
    size_t maxBits, w;
    if (nargs != 2 || !parse_counts(args[1], counts, 256, &n)) { puts("bad"); return; }
    maxNbBits = (unsigned)strtoul(args[0], NULL, 10);
    if (!huf_counts_ok(counts, (unsigned)n - 1, maxNbBits)) { puts("bad"); return; }
    for (s = 0; s < HUF_CTABLE_SIZE_ST(HUF_SYMBOLVALUE_MAX); s++) table[s] = ((HUF_CElt)FILLER_WORD << 32) | FILLER_WORD;
    maxBits = HUF_buildCTable_wksp(table, counts, (unsigned)n - 1, maxNbBits, entropy_wksp, sizeof(entropy_wksp));
    if (HUF_isError(maxBits)) { answer_error(maxBits); return; }
    printf("ok %u ", (unsigned)maxBits);
    print_words_le(table, HUF_CTABLE_SIZE_ST(HUF_SYMBOLVALUE_MAX));
    w = HUF_writeCTable_wksp(output, MAX_BYTES, table, (unsigned)n - 1, (unsigned)maxBits, entropy_wksp, sizeof(entropy_wksp));
    if (HUF_isError(w)) { printf(" err %d\n", (int)ERR_getErrorCode(w)); return; }
    putchar(' ');
    print_hex(output, w);
    puts("");
}

static void hufoptlog(char** args, int nargs)
{
    HUF_CElt table[HUF_CTABLE_SIZE_ST(HUF_SYMBOLVALUE_MAX)];
    unsigned counts[256];
    size_t total = 0;
    long n, s;
    if (nargs != 3 || !parse_counts(args[2], counts, 256, &n)) { puts("bad"); return; }
    for (s = 0; s < n; s++) total += counts[s];
    if (total < 2 || !huf_counts_ok(counts, (unsigned)n - 1, HUF_TABLELOG_MAX)) { puts("bad"); return; }
    printf("ok %u\n", HUF_optimalTableLog((unsigned)strtoul(args[0], NULL, 10), total, (unsigned)n - 1,
        entropy_wksp, sizeof(entropy_wksp), table, counts, atoi(args[1])));
}

static void hufcompress(char** args, int nargs)
{
    static HUF_CElt table[HUF_CTABLE_SIZE_ST(HUF_SYMBOLVALUE_MAX)];
    HUF_repeat repeat;
    int const hasTable = nargs == 8 && strcmp(args[6], "-") != 0;
    size_t dstCapacity, r;
    long n;
    if (nargs != 8 || (n = parse_hex(args[7])) < 0) { puts("bad"); return; }
    if (hasTable && !parse_words_le(args[6], table, HUF_CTABLE_SIZE_ST(HUF_SYMBOLVALUE_MAX))) { puts("bad"); return; }
    dstCapacity = strtoul(args[4], NULL, 10);
    repeat = (HUF_repeat)atoi(args[5]);
    if (dstCapacity > MAX_BYTES || repeat > HUF_repeat_valid) { puts("bad"); return; }
    r = atoi(args[0]) == 1
        ? HUF_compress1X_repeat(output, dstCapacity, input, (size_t)n, (unsigned)strtoul(args[1], NULL, 10),
              (unsigned)strtoul(args[2], NULL, 10), entropy_wksp, sizeof(entropy_wksp),
              hasTable ? table : NULL, hasTable ? &repeat : NULL, atoi(args[3]))
        : HUF_compress4X_repeat(output, dstCapacity, input, (size_t)n, (unsigned)strtoul(args[1], NULL, 10),
              (unsigned)strtoul(args[2], NULL, 10), entropy_wksp, sizeof(entropy_wksp),
              hasTable ? table : NULL, hasTable ? &repeat : NULL, atoi(args[3]));
    if (HUF_isError(r)) { answer_error(r); return; }
    line_reset();
    {   char head[64];
        int const k = snprintf(head, sizeof(head), "ok %u %d ", (unsigned)r, hasTable ? (int)repeat : -1);
        line_append(head, (size_t)k);
    }
    if (r == 0) line_append("-", 1);
    line_append_hex(output, r);
    line_append(" ", 1);
    if (hasTable) line_append_words_le(table, HUF_CTABLE_SIZE_ST(HUF_readCTableHeader(table).maxSymbolValue));
    else line_append("-", 1);
    puts(line_out);
}

static void hufreadctable(char** args, int nargs)
{
    HUF_CElt table[HUF_CTABLE_SIZE_ST(HUF_SYMBOLVALUE_MAX)];
    unsigned maxSV, hasZeroWeights = 0, s;
    long n;
    size_t r;
    if (nargs != 2 || (n = parse_hex(args[1])) < 0) { puts("bad"); return; }
    maxSV = (unsigned)strtoul(args[0], NULL, 10);
    if (maxSV > 255) { puts("bad"); return; }
    for (s = 0; s < HUF_CTABLE_SIZE_ST(HUF_SYMBOLVALUE_MAX); s++) table[s] = ((HUF_CElt)FILLER_WORD << 32) | FILLER_WORD;
    r = HUF_readCTable(table, &maxSV, input, (size_t)n, &hasZeroWeights);
    if (HUF_isError(r)) { answer_error(r); return; }
    printf("ok %u %u %u ", (unsigned)r, maxSV, hasZeroWeights);
    print_words_le(table, HUF_CTABLE_SIZE_ST(HUF_SYMBOLVALUE_MAX));
    puts("");
}

/* ---- Frames ---- */

static void zstdmt(void)
{
#ifdef ZSTD_MULTITHREAD
    puts("1");
#else
    puts("0");
#endif
}

static void compress(char** args, int nargs)
{
    static ZSTD_CCtx* cctx;
    size_t dstCapacity, r;
    long n;
    if (nargs != 3 || (n = parse_hex(args[2])) < 0) { puts("bad"); return; }
    dstCapacity = strtoul(args[1], NULL, 10);
    if (dstCapacity > MAX_BYTES) { puts("bad"); return; }
    if (!cctx) cctx = ZSTD_createCCtx();
    r = ZSTD_compressCCtx(cctx, output, dstCapacity, input, (size_t)n, atoi(args[0]));
    if (ZSTD_isError(r)) { answer_error(r); return; }
    line_reset();
    line_append("ok ", 3);
    line_append_hex(output, r);
    puts(line_out);
}

static unsigned long long fnv64(const unsigned char* bytes, size_t n);
static unsigned long long fnv64_from(unsigned long long hash, const void* bytes, size_t n);

/* ---- Sequences ---- */

/* ZSTD_sequenceBound(MAX_BYTES): room for the sequences of any input. */
#define MAX_SEQS (MAX_BYTES / 3 + 1 + MAX_BYTES / 1024 + 1)
#define MAX_PRODUCERS 64

/* The sequences of the cstream steps 21 to 27: given with the request, or
 * made by its steps. */
static ZSTD_Sequence seqs[MAX_SEQS];
static long long seq_values[4 * MAX_SEQS];

/* FNV-1a of sequences, each as its four fields, little-endian. */
static unsigned long long seqs_hash(const ZSTD_Sequence* s, size_t n)
{
    unsigned long long hash = 0xcbf29ce484222325ULL;
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned char b[16];
        MEM_writeLE32(b, s[i].offset);
        MEM_writeLE32(b + 4, s[i].litLength);
        MEM_writeLE32(b + 8, s[i].matchLength);
        MEM_writeLE32(b + 12, s[i].rep);
        hash = fnv64_from(hash, b, 16);
    }
    return hash;
}

/* The sequence producer of the cstream step 19, mirrored by the Rust tests:
 * a greedy match finder over the block alone (no history), deterministic,
 * that fails as it is told.
 *   kind & 3: 0 matches of 4 bytes or more, from a hash table of 2^(8 +
 *             level % 8) entries; 1 the same, of 3 bytes or more; 2 only
 *             literals, one delimiter; 3 as 0, the last offset tried first
 *             (repeat offsets);
 *   kind & 4: always ends with a delimiter, of no literals if need be
 *             (otherwise only when literals are left);
 *   kind & 8: the delimiter without the last literals (a parse that does
 *             not add up);
 *   kind & 16: every fifth match cut to 2 bytes (too short);
 *   kind & 32: every third match with an offset of 2^31 - 1 (too far).
 * Every errorEvery-th call (none for 0) fails instead, in turn returning
 * ZSTD_SEQUENCE_PRODUCER_ERROR, the room plus 1, 0, and the room filled
 * with sequences, no delimiter last. */
typedef struct {
    unsigned kind;
    unsigned errorEvery;
    unsigned calls;
} OracleProducer;

static U32 producer_table[1 << 15];

static size_t oracle_producer(void* opaque, ZSTD_Sequence* outSeqs, size_t outSeqsCapacity,
                              const void* src, size_t srcSize, const void* dict, size_t dictSize,
                              int compressionLevel, size_t windowSize)
{
    OracleProducer* const state = (OracleProducer*)opaque;
    const BYTE* const base = (const BYTE*)src;
    unsigned const call = state->calls++;
    unsigned const variant = state->kind & 3;
    size_t const mls = variant == 1 ? 3 : 4;
    unsigned const hashLog = 8 + (unsigned)(compressionLevel < 0 ? 0 : compressionLevel % 8);
    size_t pos = 0, anchor = 0, n = 0;
    U32 lastOffset = 0;
    (void)dict;
    (void)dictSize;
    if (state->errorEvery != 0 && call % state->errorEvery == state->errorEvery - 1) {
        switch ((call / state->errorEvery) % 4) {
        case 0: return ZSTD_SEQUENCE_PRODUCER_ERROR;
        case 1: return outSeqsCapacity + 1;
        case 2: return 0;
        default: {
            size_t i;
            for (i = 0; i < outSeqsCapacity; i++) {
                outSeqs[i].offset = 1;
                outSeqs[i].litLength = 0;
                outSeqs[i].matchLength = 1;
                outSeqs[i].rep = 0;
            }
            return outSeqsCapacity;
        } }
    }
    if (variant == 2) {
        outSeqs[0].offset = 0;
        outSeqs[0].litLength = (U32)srcSize;
        outSeqs[0].matchLength = 0;
        outSeqs[0].rep = 0;
        return 1;
    }
    memset(producer_table, 0, sizeof(U32) << hashLog);
    while (pos + 4 <= srcSize && n + 2 < outSeqsCapacity) {
        size_t length = 0;
        int found = 0;
        size_t matchStart = 0;
        if (variant == 3 && lastOffset != 0 && lastOffset <= pos) {
            size_t const cand = pos - lastOffset;
            while (pos + length < srcSize && base[cand + length] == base[pos + length]) length++;
            if (length >= mls) { found = 1; matchStart = cand; } else length = 0;
        }
        {   U32 const value = mls == 3
                ? (U32)base[pos] | (U32)base[pos + 1] << 8 | (U32)base[pos + 2] << 16
                : MEM_readLE32(base + pos);
            U32 const h = (value * 2654435761u) >> (32 - hashLog);
            U32 const cand = producer_table[h];
            producer_table[h] = (U32)pos + 1;
            if (!found && cand != 0 && pos - (cand - 1) <= windowSize) {
                size_t const c = cand - 1;
                while (pos + length < srcSize && base[c + length] == base[pos + length]) length++;
                if (length >= mls) { found = 1; matchStart = c; } else length = 0;
            }
        }
        if (!found) { pos++; continue; }
        {   U32 offset = (U32)(pos - matchStart);
            lastOffset = offset;
            if ((state->kind & 16) && n % 5 == 4) length = 2;
            if ((state->kind & 32) && n % 3 == 2) offset = 0x7FFFFFFF;
            outSeqs[n].offset = offset;
            outSeqs[n].litLength = (U32)(pos - anchor);
            outSeqs[n].matchLength = (U32)length;
            outSeqs[n].rep = 0;
            n++;
            pos += length;
            anchor = pos;
        }
    }
    if ((state->kind & 4) || anchor < srcSize) {
        outSeqs[n].offset = 0;
        outSeqs[n].litLength = (state->kind & 8) ? 0 : (U32)(srcSize - anchor);
        outSeqs[n].matchLength = 0;
        outSeqs[n].rep = 0;
        n++;
    }
    return n;
}

/* A new compression context through steps of three numbers, op a b, over
 * `input` and `output` (of capacity `cap`), from where the last step left
 * them:
 *   0, 1, 2: ZSTD_compressStream2 with ZSTD_e_continue, _flush, _end, the
 *            input up to a more bytes, the output up to b more;
 *   3: ZSTD_compressStream, 4: ZSTD_flushStream, 5: ZSTD_endStream;
 *   6: ZSTD_compress2 of the next a bytes into the next b;
 *   7: ZSTD_CCtx_setParameter(a, b); 8: ZSTD_CCtx_reset(a);
 *   9: ZSTD_CCtx_setPledgedSrcSize(a, or unknown if a < 0);
 *   10: ZSTD_compressStream2 with ZSTD_e_continue, the input up to a more
 *       bytes, its position moved b further, and all the room left.
 * With the dictionary bytes <dicthex>, an optional fourth argument, the
 * steps that set a dictionary, from the b bytes at a of them (cut to them):
 *   11, 12, 13: ZSTD_CCtx_loadDictionary_advanced, by copy, as
 *       ZSTD_dct_auto, _rawContent, _fullDict;
 *   14: ZSTD_CCtx_refPrefix; 15: ZSTD_CCtx_refPrefix_advanced, ZSTD_dct_auto;
 * and from the first a bytes of them:
 *   16: ZSTD_CCtx_refCDict of ZSTD_createCDict at level b;
 *   17: ZSTD_CCtx_refCDict of ZSTD_createCDict_advanced2, by copy, with the
 *       context's requested parameters, as ZSTD_dct_auto, _rawContent,
 *       _fullDict for b 0, 1, 2;
 *   18: ZSTD_CCtx_refCDict(NULL).
 * With the sequences <seqs>, an optional fifth argument (quadruples offset,
 * litLength, matchLength, rep; <dicthex> "-" for none), the steps of the
 * sequence API, over "the window": sequences first a, b of them (all of
 * them at first):
 *   19: ZSTD_registerSequenceProducer, of the producer above (oracle_producer)
 *       with the kind a and errorEvery b, a new state;
 *   20: ZSTD_registerSequenceProducer(NULL);
 *   21: ZSTD_compressSequences of the window, over the next a bytes of input,
 *       into the next b of output;
 *   22: ZSTD_compressSequencesAndLiterals of the window, the next a bytes of
 *       input as the literals (their capacity the rest of the buffer), into
 *       the next b of output, of the decompressed size set by 24 (or, if
 *       negative, the window's lengths); then the input goes on that much
 *       further, past the bytes the frame stands for;
 *   23: the window: sequences a to a + b (b < 0: all of those after a);
 *   24: the decompressed size of 22;
 *   25: ZSTD_generateSequences of the next a bytes of input, into the
 *       sequences, b of room (b < 0: ZSTD_sequenceBound), zeroed first;
 *       the input stays where it is, and the sequences made become the
 *       window, answered "<result>/<positions>:<FNV-1a of the sequences>";
 *   26: ZSTD_CCtx_getParameter(a), answered "v<value>";
 *   27: ZSTD_mergeBlockDelimiters of the window, which becomes the sequences
 *       left, answered "m<count>:<FNV-1a of them>";
 *   28: nothing (the Rust side then checks that the frames of 21 and 22
 *       decode back).
 * Answers each step's result (s for success of 7 to 9, 11 to 20, 23, 24 and
 * 28, n for a CDict not made) with the positions, then a hash of the
 * output. After an error of a compression call (0 to 6, 10), the session is
 * reset, as a context must be before it is used again; but for buffers not
 * as stable as promised, which is found before anything changes. */
static void cstream(char** args, int nargs)
{
    static long long steps[3 * 4096];
    static unsigned char dict[MAX_BYTES];
    static ZSTD_CDict* cdicts[4096];
    static OracleProducer producers[MAX_PRODUCERS];
    ZSTD_CCtx* cctx;
    size_t cap, r, inPos = 0, outPos = 0;
    size_t nseqs = 0, winFirst = 0, winCount = 0;
    long long decompressed = -1;
    long n, nsteps, i, dictSize = 0, ncdicts = 0, nproducers = 0;
    char text[80];
    if ((nargs < 3 || nargs > 5) || (n = parse_hex(args[2])) < 0) { puts("bad"); return; }
    if (nargs >= 4 && (dictSize = parse_hex_into(args[3], dict)) < 0) { puts("bad"); return; }
    if (nargs == 5) {
        long const values = parse_list(args[4], seq_values, 4 * MAX_SEQS);
        long k;
        if (values < 0 || values % 4) { puts("bad"); return; }
        nseqs = (size_t)values / 4;
        for (k = 0; k < (long)nseqs; k++) {
            seqs[k].offset = (unsigned)seq_values[4 * k];
            seqs[k].litLength = (unsigned)seq_values[4 * k + 1];
            seqs[k].matchLength = (unsigned)seq_values[4 * k + 2];
            seqs[k].rep = (unsigned)seq_values[4 * k + 3];
        }
        winCount = nseqs;
    }
    cap = strtoul(args[0], NULL, 10);
    nsteps = parse_list(args[1], steps, 3 * 4096);
    if (cap > MAX_BYTES || nsteps < 0 || nsteps % 3) { puts("bad"); return; }
    cctx = ZSTD_createCCtx();
    line_reset();
    line_append("ok", 2);
    for (i = 0; i < nsteps; i += 3) {
        long long const op = steps[i], a = steps[i + 1], b = steps[i + 2];
        size_t const inEnd = inPos + (size_t)(a < 0 ? 0 : a);
        size_t const outEnd = outPos + (size_t)(b < 0 ? 0 : b);
        /* The dictionary's bytes: b at a, or the first a. */
        size_t const dictAt = (size_t)(a < 0 ? 0 : a) < (size_t)dictSize ? (size_t)(a < 0 ? 0 : a) : (size_t)dictSize;
        size_t const dictLen = (size_t)(b < 0 ? 0 : b) < (size_t)dictSize - dictAt ? (size_t)(b < 0 ? 0 : b) : (size_t)dictSize - dictAt;
        int noCDict = 0;
        int value = 0;
        ZSTD_inBuffer in;
        ZSTD_outBuffer out;
        in.src = input;
        in.size = inEnd < (size_t)n ? inEnd : (size_t)n;
        in.pos = inPos;
        out.dst = output;
        out.size = outEnd < cap ? outEnd : cap;
        out.pos = outPos;
        switch (op) {
        case 0: case 1: case 2:
            r = ZSTD_compressStream2(cctx, &out, &in, (ZSTD_EndDirective)op);
            break;
        case 3: r = ZSTD_compressStream(cctx, &out, &in); break;
        case 4: r = ZSTD_flushStream(cctx, &out); break;
        case 5: r = ZSTD_endStream(cctx, &out); break;
        case 6:
            r = ZSTD_compress2(cctx, output + outPos, out.size - outPos, input + inPos,
                               in.size - inPos);
            if (!ZSTD_isError(r)) { in.pos = in.size; out.pos = outPos + r; }
            break;
        case 10:
            in.pos = inPos + (size_t)b < in.size ? inPos + (size_t)b : in.size;
            out.size = cap;
            r = ZSTD_compressStream2(cctx, &out, &in, ZSTD_e_continue);
            break;
        case 7: r = ZSTD_CCtx_setParameter(cctx, (ZSTD_cParameter)a, (int)b); break;
        case 8: r = ZSTD_CCtx_reset(cctx, (ZSTD_ResetDirective)a); break;
        case 9:
            r = ZSTD_CCtx_setPledgedSrcSize(cctx, a < 0 ? ZSTD_CONTENTSIZE_UNKNOWN
                                                        : (unsigned long long)a);
            break;
        case 11: case 12: case 13:
            r = ZSTD_CCtx_loadDictionary_advanced(cctx, dict + dictAt, dictLen, ZSTD_dlm_byCopy,
                    op == 11 ? ZSTD_dct_auto : op == 12 ? ZSTD_dct_rawContent : ZSTD_dct_fullDict);
            break;
        case 14: r = ZSTD_CCtx_refPrefix(cctx, dict + dictAt, dictLen); break;
        case 15: r = ZSTD_CCtx_refPrefix_advanced(cctx, dict + dictAt, dictLen, ZSTD_dct_auto); break;
        case 16: case 17: {
            size_t const len = (size_t)(a < 0 ? 0 : a) < (size_t)dictSize ? (size_t)(a < 0 ? 0 : a) : (size_t)dictSize;
            ZSTD_CDict* const cdict = op == 16
                ? ZSTD_createCDict(dict, len, (int)b)
                : ZSTD_createCDict_advanced2(dict, len, ZSTD_dlm_byCopy,
                      b == 1 ? ZSTD_dct_rawContent : b == 2 ? ZSTD_dct_fullDict : ZSTD_dct_auto,
                      &cctx->requestedParams, ZSTD_defaultCMem);
            if (cdict == NULL) { noCDict = 1; r = 0; break; }
            cdicts[ncdicts++] = cdict;
            r = ZSTD_CCtx_refCDict(cctx, cdict);
            break;
        }
        case 18: r = ZSTD_CCtx_refCDict(cctx, NULL); break;
        case 19:
            if (nproducers == MAX_PRODUCERS) goto bad;
            producers[nproducers].kind = (unsigned)a;
            producers[nproducers].errorEvery = (unsigned)b;
            producers[nproducers].calls = 0;
            ZSTD_registerSequenceProducer(cctx, &producers[nproducers++], oracle_producer);
            r = 0;
            break;
        case 20: ZSTD_registerSequenceProducer(cctx, NULL, NULL); r = 0; break;
        case 21:
            r = ZSTD_compressSequences(cctx, output + outPos, out.size - outPos,
                                       seqs + winFirst, winCount, input + inPos, in.size - inPos);
            if (!ZSTD_isError(r)) { in.pos = in.size; out.pos = outPos + r; }
            break;
        case 22: {
            size_t const litSize = in.size - inPos;
            size_t total = 0, k;
            for (k = 0; k < winCount; k++)
                total += (size_t)seqs[winFirst + k].litLength + (size_t)seqs[winFirst + k].matchLength;
            {   size_t const dSize = decompressed < 0 ? total : (size_t)decompressed;
                r = ZSTD_compressSequencesAndLiterals(cctx, output + outPos, out.size - outPos,
                        seqs + winFirst, winCount, input + inPos, litSize, MAX_BYTES - inPos, dSize);
                if (!ZSTD_isError(r)) {
                    in.pos = dSize < (size_t)n - in.size ? in.size + dSize : (size_t)n;
                    out.pos = outPos + r;
                }
            }
            break;
        }
        case 23:
            winFirst = (size_t)(a < 0 ? 0 : a) < nseqs ? (size_t)(a < 0 ? 0 : a) : nseqs;
            winCount = b < 0 || (size_t)b > nseqs - winFirst ? nseqs - winFirst : (size_t)b;
            r = 0;
            break;
        case 24: decompressed = a; r = 0; break;
        case 25: {
            size_t const srcSize = in.size - inPos;
            size_t const room = b < 0 ? ZSTD_sequenceBound(srcSize) : (size_t)b;
            if (room > MAX_SEQS) goto bad;
            memset(seqs, 0, room * sizeof(ZSTD_Sequence));
            r = ZSTD_generateSequences(cctx, seqs, room, input + inPos, srcSize);
            if (!ZSTD_isError(r)) { nseqs = r; winFirst = 0; winCount = r; }
            in.pos = inPos;
            break;
        }
        case 26: r = ZSTD_CCtx_getParameter(cctx, (ZSTD_cParameter)a, &value); break;
        case 27: winCount = ZSTD_mergeBlockDelimiters(seqs + winFirst, winCount); r = 0; break;
        case 28: r = 0; break;
        default:
        bad:
            ZSTD_freeCCtx(cctx);
            while (ncdicts > 0) ZSTD_freeCDict(cdicts[--ncdicts]);
            puts("bad");
            return;
        }
        inPos = in.pos;
        outPos = out.pos;
        if (ZSTD_isError(r) && (op <= 6 || op == 10)
            && ERR_getErrorCode(r) != ZSTD_error_stabilityCondition_notRespected)
            ZSTD_CCtx_reset(cctx, ZSTD_reset_session_only);
        if (ZSTD_isError(r))
            snprintf(text, sizeof(text), " e%d/%u/%u", (int)ERR_getErrorCode(r),
                     (unsigned)inPos, (unsigned)outPos);
        else if (noCDict)
            snprintf(text, sizeof(text), " n");
        else if (op == 25)
            snprintf(text, sizeof(text), " %u/%u/%u:%016llx", (unsigned)r, (unsigned)inPos,
                     (unsigned)outPos, seqs_hash(seqs, r));
        else if (op == 26)
            snprintf(text, sizeof(text), " v%d", value);
        else if (op == 27)
            snprintf(text, sizeof(text), " m%u:%016llx", (unsigned)winCount,
                     seqs_hash(seqs + winFirst, winCount));
        else if ((op >= 7 && op <= 9) || (op >= 11 && op != 21 && op != 22))
            snprintf(text, sizeof(text), " s");
        else
            snprintf(text, sizeof(text), " %u/%u/%u", (unsigned)r, (unsigned)inPos,
                     (unsigned)outPos);
        line_append(text, strlen(text));
    }
    ZSTD_freeCCtx(cctx);
    while (ncdicts > 0) ZSTD_freeCDict(cdicts[--ncdicts]);
    snprintf(text, sizeof(text), " %016llx", fnv64(output, outPos));
    line_append(text, strlen(text));
    puts(line_out);
}

/* ---- A block's entropy coding ---- */

static ZSTD_entropyCTables_t seq_entropy[2];
static int seq_prev;
static U32 seq_wksp[TMP_WORKSPACE_SIZE / sizeof(U32)];

static void seqreset(int nargs)
{
    int i;
    size_t w;
    if (nargs != 0) { puts("bad"); return; }
    for (i = 0; i < 2; i++) {
        ZSTD_entropyCTables_t* const e = &seq_entropy[i];
        for (w = 0; w < HUF_CTABLE_SIZE_ST(255); w++) e->huf.CTable[w] = ((HUF_CElt)FILLER_WORD << 32) | FILLER_WORD;
        for (w = 0; w < sizeof(e->fse.offcodeCTable) / 4; w++) e->fse.offcodeCTable[w] = FILLER_WORD;
        for (w = 0; w < sizeof(e->fse.matchlengthCTable) / 4; w++) e->fse.matchlengthCTable[w] = FILLER_WORD;
        for (w = 0; w < sizeof(e->fse.litlengthCTable) / 4; w++) e->fse.litlengthCTable[w] = FILLER_WORD;
        e->huf.repeatMode = HUF_repeat_none;
        e->fse.offcode_repeatMode = FSE_repeat_none;
        e->fse.matchlength_repeatMode = FSE_repeat_none;
        e->fse.litlength_repeatMode = FSE_repeat_none;
    }
    seq_prev = 0;
    puts("ok");
}

static unsigned long long fnv64_from(unsigned long long hash, const void* bytes, size_t n)
{
    const unsigned char* const p = (const unsigned char*)bytes;
    size_t i;
    for (i = 0; i < n; i++) {
        hash ^= p[i];
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

/* The tables as little-endian bytes: FSE words, then Huffman elements up to
 * the table's largest symbol. */
static unsigned long long entropy_digest(const ZSTD_entropyCTables_t* e)
{
    unsigned long long hash = 0xcbf29ce484222325ULL;
    size_t w;
    const FSE_CTable* const tables[3] = { e->fse.offcodeCTable, e->fse.matchlengthCTable, e->fse.litlengthCTable };
    size_t const sizes[3] = { sizeof(e->fse.offcodeCTable) / 4, sizeof(e->fse.matchlengthCTable) / 4, sizeof(e->fse.litlengthCTable) / 4 };
    int t;
    for (t = 0; t < 3; t++) {
        for (w = 0; w < sizes[t]; w++) {
            unsigned char bytes[4];
            int b;
            for (b = 0; b < 4; b++) bytes[b] = (unsigned char)(tables[t][w] >> (8 * b));
            hash = fnv64_from(hash, bytes, 4);
        }
    }
    for (w = 0; w < HUF_CTABLE_SIZE_ST(HUF_readCTableHeader(e->huf.CTable).maxSymbolValue); w++) {
        unsigned char bytes[8];
        int b;
        for (b = 0; b < 8; b++) bytes[b] = (unsigned char)((unsigned long long)e->huf.CTable[w] >> (8 * b));
        hash = fnv64_from(hash, bytes, 8);
    }
    return hash;
}

static void seqblock(char** args, int nargs)
{
    static SeqDef sequences[ZSTD_BLOCKSIZE_MAX / MINMATCH + 1];
    static BYTE llCode[ZSTD_BLOCKSIZE_MAX / MINMATCH + 1], mlCode[ZSTD_BLOCKSIZE_MAX / MINMATCH + 1], ofCode[ZSTD_BLOCKSIZE_MAX / MINMATCH + 1];
    static BYTE literals[ZSTD_BLOCKSIZE_MAX];
    static long long triples[3 * (ZSTD_BLOCKSIZE_MAX / MINMATCH + 1)];
    SeqStore_t seqStore;
    ZSTD_CCtx_params params;
    size_t dstCapacity, blockSize, r;
    long litSize, n, i;
    int strategy;
    if (nargs != 6 || (litSize = parse_hex(args[4])) < 0 || litSize > ZSTD_BLOCKSIZE_MAX) { puts("bad"); return; }
    memcpy(literals, input, (size_t)litSize);
    n = parse_list(args[5], triples, 3 * (ZSTD_BLOCKSIZE_MAX / MINMATCH + 1));
    strategy = atoi(args[0]);
    dstCapacity = strtoul(args[3], NULL, 10);
    if (n < 0 || n % 3 || strategy < ZSTD_fast || strategy > ZSTD_btultra2 || dstCapacity > MAX_BYTES) { puts("bad"); return; }
    memset(&seqStore, 0, sizeof(seqStore));
    seqStore.sequencesStart = sequences;
    seqStore.litStart = literals;
    seqStore.lit = literals + litSize;
    seqStore.llCode = llCode;
    seqStore.mlCode = mlCode;
    seqStore.ofCode = ofCode;
    seqStore.maxNbSeq = ZSTD_BLOCKSIZE_MAX / MINMATCH + 1;
    seqStore.maxNbLit = ZSTD_BLOCKSIZE_MAX;
    seqStore.longLengthType = ZSTD_llt_none;
    blockSize = (size_t)litSize;
    for (i = 0; i < n / 3; i++) {
        long long const offBase = triples[3 * i], litLength = triples[3 * i + 1], matchLength = triples[3 * i + 2];
        if (offBase < 1 || offBase > 0xFFFFFFFFLL || litLength < 0 || matchLength < MINMATCH
            || litLength > 0x1FFFF || matchLength - MINMATCH > 0x1FFFF) { puts("bad"); return; }
        if (litLength > 0xFFFF || matchLength - MINMATCH > 0xFFFF) {
            if (seqStore.longLengthType != ZSTD_llt_none) { puts("bad"); return; }
            seqStore.longLengthType = litLength > 0xFFFF ? ZSTD_llt_literalLength : ZSTD_llt_matchLength;
            seqStore.longLengthPos = (U32)i;
        }
        sequences[i].offBase = (U32)offBase;
        sequences[i].litLength = (U16)litLength;
        sequences[i].mlBase = (U16)(matchLength - MINMATCH);
        blockSize += (size_t)matchLength;
    }
    seqStore.sequences = sequences + n / 3;
    if (blockSize > ZSTD_BLOCKSIZE_MAX) { puts("bad"); return; }
    memset(&params, 0, sizeof(params));
    params.cParams.strategy = (ZSTD_strategy)strategy;
    params.cParams.targetLength = (unsigned)strtoul(args[2], NULL, 10);
    params.literalCompressionMode = (ZSTD_ParamSwitch_e)atoi(args[1]);
    r = ZSTD_entropyCompressSeqStore(&seqStore, &seq_entropy[seq_prev], &seq_entropy[1 - seq_prev], &params,
                                     output, dstCapacity, blockSize, seq_wksp, sizeof(seq_wksp), 0);
    if (ZSTD_isError(r)) { answer_error(r); return; }
    if (r > 1) seq_prev = 1 - seq_prev;
    if (seq_entropy[seq_prev].fse.offcode_repeatMode == FSE_repeat_valid)
        seq_entropy[seq_prev].fse.offcode_repeatMode = FSE_repeat_check;
    line_reset();
    {   char head[64];
        int const k = snprintf(head, sizeof(head), "ok %u ", (unsigned)r);
        line_append(head, (size_t)k);
    }
    if (r == 0) line_append("-", 1);
    line_append_hex(output, r);
    {   const ZSTD_entropyCTables_t* const e = &seq_entropy[seq_prev];
        char tail[96];
        int const k = snprintf(tail, sizeof(tail), " %d,%d,%d,%d %016llx", (int)e->huf.repeatMode,
            (int)e->fse.offcode_repeatMode, (int)e->fse.matchlength_repeatMode,
            (int)e->fse.litlength_repeatMode, entropy_digest(e));
        line_append(tail, (size_t)k);
    }
    puts(line_out);
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

static void stream(char** args, int nargs)
{
    static long long steps[2 * 1024];
    ZSTD_DCtx* dctx;
    size_t cap, r, inPos = 0, outPos = 0;
    long n, nsteps, i;
    int stable;
    char text[80];
    if (nargs != 6 || (n = parse_hex(args[5])) < 0) { puts("bad"); return; }
    cap = strtoul(args[3], NULL, 10);
    nsteps = parse_list(args[4], steps, 2 * 1024);
    if (cap > MAX_BYTES || nsteps < 0 || nsteps % 2) { puts("bad"); return; }
    stable = atoi(args[1]);
    dctx = ZSTD_createDCtx();
    r = ZSTD_DCtx_setParameter(dctx, ZSTD_d_maxBlockSize, atoi(args[0]));
    if (!ZSTD_isError(r)) r = ZSTD_DCtx_setParameter(dctx, ZSTD_d_stableOutBuffer, stable);
    if (!ZSTD_isError(r)) r = ZSTD_DCtx_setParameter(dctx, ZSTD_d_windowLogMax, atoi(args[2]));
    if (ZSTD_isError(r)) { ZSTD_freeDCtx(dctx); answer_error(r); return; }
    line_reset();
    line_append("ok", 2);
    for (i = 0; i < nsteps; i += 2) {
        ZSTD_inBuffer in;
        ZSTD_outBuffer out;
        size_t const inEnd = inPos + (size_t)steps[i];
        size_t const outEnd = outPos + (size_t)steps[i + 1];
        in.src = input;
        in.size = inEnd < (size_t)n ? inEnd : (size_t)n;
        in.pos = inPos;
        out.dst = output;
        out.size = stable || outEnd > cap ? cap : outEnd;
        out.pos = outPos;
        r = ZSTD_decompressStream(dctx, &out, &in);
        inPos = in.pos;
        outPos = out.pos;
        if (ZSTD_isError(r))
            snprintf(text, sizeof(text), " e%d/%u/%u", (int)ERR_getErrorCode(r),
                     (unsigned)inPos, (unsigned)outPos);
        else
            snprintf(text, sizeof(text), " %u/%u/%u", (unsigned)r, (unsigned)inPos,
                     (unsigned)outPos);
        line_append(text, strlen(text));
    }
    ZSTD_freeDCtx(dctx);
    snprintf(text, sizeof(text), " %016llx", fnv64(output, outPos));
    line_append(text, strlen(text));
    puts(line_out);
}

/* ---- The dictionary builder ---- */

#if defined(__APPLE__)
/* glibc's merge sort (msort_with_tmp), which cover.c's stableSort gets on
 * Linux: the halves sorted in place, then merged through `tmp`, comparing
 * elements where they lie in `base`, the left one first on ties. */
static void oracle_msort(char* b, size_t n, size_t s, char* tmp, void* thunk,
                         int (*compar)(void*, const void*, const void*))
{
    size_t n1, n2;
    char *b1, *b2, *t = tmp;
    if (n <= 1) return;
    n1 = n / 2;
    n2 = n - n1;
    b1 = b;
    b2 = b + n1 * s;
    oracle_msort(b1, n1, s, tmp, thunk, compar);
    oracle_msort(b2, n2, s, tmp, thunk, compar);
    while (n1 > 0 && n2 > 0) {
        if (compar(thunk, b1, b2) <= 0) { memcpy(t, b1, s); b1 += s; n1--; }
        else { memcpy(t, b2, s); b2 += s; n2--; }
        t += s;
    }
    if (n1 > 0) memcpy(t, b1, n1 * s);
    memcpy(b, tmp, (n - n2) * s);
}

/* In place of Apple's (FreeBSD's quicksort), for cover.c: see the comment
 * at the top. */
void qsort_r(void* base, size_t nel, size_t width, void* thunk,
             int (*compar)(void*, const void*, const void*))
{
    char* tmp = (char*)malloc(nel * width + 1);
    if (!tmp) abort();
    oracle_msort((char*)base, nel, width, tmp, thunk, compar);
    free(tmp);
}
#endif

/* libzstd's notifications on stderr (notificationLevel), silenced while the
 * dictionary builder runs. */
static int zd_stderr = -1;

static void zd_quiet(void)
{
    int null = open("/dev/null", O_WRONLY);
    fflush(stderr);
    if (zd_stderr < 0) zd_stderr = dup(2);
    if (null >= 0) { dup2(null, 2); close(null); }
}

static void zd_loud(void)
{
    fflush(stderr);
    if (zd_stderr >= 0) dup2(zd_stderr, 2);
}

#define ZD_MAX_SAMPLES (1 << 16)
static size_t zd_sizes[ZD_MAX_SAMPLES];
static long long zd_values[ZD_MAX_SAMPLES];
static unsigned char zd_content[MAX_BYTES];
static unsigned char zd_dict[MAX_BYTES];

/* The samples' sizes and bytes; their number, or -1 when they do not add
 * up. */
static long zd_samples(const char* sizes, const char* hex)
{
    long n = parse_list(sizes, zd_values, ZD_MAX_SAMPLES), i, bytes = parse_hex(hex);
    size_t total = 0;
    if (n < 0 || bytes < 0) return -1;
    for (i = 0; i < n; i++) {
        if (zd_values[i] < 0) return -1;
        zd_sizes[i] = (size_t)zd_values[i];
        total += zd_sizes[i];
    }
    if (total != (size_t)bytes) return -1;
    return n;
}

static int zd_zparams(const long long* v, ZDICT_params_t* p)
{
    memset(p, 0, sizeof(*p));
    p->compressionLevel = (int)v[0];
    p->notificationLevel = (unsigned)v[1];
    p->dictID = (unsigned)v[2];
    return 1;
}

static int zd_cover(const char* text, ZDICT_cover_params_t* p)
{
    long long v[10];
    if (parse_list(text, v, 10) != 10) return 0;
    memset(p, 0, sizeof(*p));
    p->k = (unsigned)v[0];
    p->d = (unsigned)v[1];
    p->steps = (unsigned)v[2];
    p->nbThreads = (unsigned)v[3];
    p->splitPoint = (double)v[4] / 1000.0;
    p->shrinkDict = (unsigned)v[5];
    p->shrinkDictMaxRegression = (unsigned)v[6];
    return zd_zparams(v + 7, &p->zParams);
}

static int zd_fastcover(const char* text, ZDICT_fastCover_params_t* p)
{
    long long v[12];
    if (parse_list(text, v, 12) != 12) return 0;
    memset(p, 0, sizeof(*p));
    p->k = (unsigned)v[0];
    p->d = (unsigned)v[1];
    p->f = (unsigned)v[2];
    p->steps = (unsigned)v[3];
    p->nbThreads = (unsigned)v[4];
    p->splitPoint = (double)v[5] / 1000.0;
    p->accel = (unsigned)v[6];
    p->shrinkDict = (unsigned)v[7];
    p->shrinkDictMaxRegression = (unsigned)v[8];
    return zd_zparams(v + 9, &p->zParams);
}

static unsigned long long zd_bits(double d)
{
    unsigned long long bits;
    memcpy(&bits, &d, sizeof(bits));
    return bits;
}

/* "ok <hex>" of the dictionary in `zd_dict`, with `tail` after it. */
static void zd_answer(size_t r, const char* tail)
{
    if (ZDICT_isError(r)) { answer_error(r); return; }
    line_reset();
    line_append("ok ", 3);
    line_append_hex(zd_dict, r);
    line_append(tail, strlen(tail));
    puts(line_out);
}

static void zdtrain(char** args, int nargs, int fast, int optimize)
{
    char tail[512] = "";
    size_t capacity, r;
    long n;
    if (nargs != 4 || (n = zd_samples(args[2], args[3])) < 0) { puts("bad"); return; }
    capacity = strtoul(args[0], NULL, 10);
    if (capacity > MAX_BYTES) { puts("bad"); return; }
    if (fast) {
        ZDICT_fastCover_params_t p;
        if (!zd_fastcover(args[1], &p)) { puts("bad"); return; }
        zd_quiet();
        if (optimize) {
            r = ZDICT_optimizeTrainFromBuffer_fastCover(zd_dict, capacity, input, zd_sizes, (unsigned)n, &p);
            snprintf(tail, sizeof(tail), " %u,%u,%u,%u,%u,%016llx,%u,%u,%u,%d,%u,%u",
                     p.k, p.d, p.f, p.steps, p.nbThreads, zd_bits(p.splitPoint), p.accel,
                     p.shrinkDict, p.shrinkDictMaxRegression, p.zParams.compressionLevel,
                     p.zParams.notificationLevel, p.zParams.dictID);
        } else {
            r = ZDICT_trainFromBuffer_fastCover(zd_dict, capacity, input, zd_sizes, (unsigned)n, p);
        }
    } else {
        ZDICT_cover_params_t p;
        if (!zd_cover(args[1], &p)) { puts("bad"); return; }
        zd_quiet();
        if (optimize) {
            r = ZDICT_optimizeTrainFromBuffer_cover(zd_dict, capacity, input, zd_sizes, (unsigned)n, &p);
            snprintf(tail, sizeof(tail), " %u,%u,%u,%u,%016llx,%u,%u,%d,%u,%u",
                     p.k, p.d, p.steps, p.nbThreads, zd_bits(p.splitPoint), p.shrinkDict,
                     p.shrinkDictMaxRegression, p.zParams.compressionLevel,
                     p.zParams.notificationLevel, p.zParams.dictID);
        } else {
            r = ZDICT_trainFromBuffer_cover(zd_dict, capacity, input, zd_sizes, (unsigned)n, p);
        }
    }
    zd_loud();
    zd_answer(r, tail);
}

static void zdfinalize(char** args, int nargs)
{
    long long v[3];
    ZDICT_params_t p;
    size_t capacity, r;
    long n, contentSize;
    if (nargs != 5 || parse_list(args[1], v, 3) != 3
        || (contentSize = parse_hex_into(args[2], zd_content)) < 0
        || (n = zd_samples(args[3], args[4])) < 0) { puts("bad"); return; }
    capacity = strtoul(args[0], NULL, 10);
    if (capacity > MAX_BYTES) { puts("bad"); return; }
    zd_zparams(v, &p);
    zd_quiet();
    r = ZDICT_finalizeDictionary(zd_dict, capacity, zd_content, (size_t)contentSize, input,
                                 zd_sizes, (unsigned)n, p);
    zd_loud();
    zd_answer(r, "");
}

static void zdadd(char** args, int nargs)
{
    long long v[3];
    ZDICT_params_t p;
    size_t contentSize, r;
    long n, capacity;
    if (nargs != 5 || parse_list(args[1], v, 3) != 3
        || (capacity = parse_hex_into(args[2], zd_dict)) < 8
        || (n = zd_samples(args[3], args[4])) < 0) { puts("bad"); return; }
    contentSize = strtoul(args[0], NULL, 10);
    if (contentSize > (size_t)capacity) { puts("bad"); return; }
    zd_zparams(v, &p);
    zd_quiet();
    r = ZDICT_addEntropyTablesFromBuffer_advanced(zd_dict, contentSize, (size_t)capacity, input,
                                                  zd_sizes, (unsigned)n, p);
    zd_loud();
    zd_answer(r, "");
}

static void zdentropy(char** args, int nargs)
{
    size_t capacity;
    long n, contentSize;
    if (nargs != 5 || (contentSize = parse_hex_into(args[2], zd_content)) < 0
        || (n = zd_samples(args[3], args[4])) < 0) { puts("bad"); return; }
    capacity = strtoul(args[0], NULL, 10);
    if (capacity > MAX_BYTES) { puts("bad"); return; }
    zd_answer(ZDICT_analyzeEntropy(zd_dict, capacity, atoi(args[1]), input, zd_sizes,
                                   (unsigned)n, zd_content, (size_t)contentSize, 0), "");
}

static void zdselect(char** args, int nargs)
{
    static size_t offsets[ZD_MAX_SAMPLES + 1];
    ZDICT_cover_params_t p;
    COVER_dictSelection_t s;
    size_t capacity, nbFinalize, nbCheck, i;
    long n, contentSize;
    char tail[32];
    if (nargs != 7 || !zd_cover(args[1], &p)
        || (contentSize = parse_hex_into(args[2], zd_content)) < 0
        || (n = zd_samples(args[5], args[6])) < 0) { puts("bad"); return; }
    capacity = strtoul(args[0], NULL, 10);
    nbFinalize = strtoul(args[3], NULL, 10);
    nbCheck = strtoul(args[4], NULL, 10);
    if (capacity > MAX_BYTES || (size_t)contentSize > capacity || nbFinalize > (size_t)n
        || nbCheck > (size_t)n) { puts("bad"); return; }
    offsets[0] = 0;
    for (i = 0; i < (size_t)n; i++) offsets[i + 1] = offsets[i] + zd_sizes[i];
    /* The content at the end of the buffer, zeros before it, where
     * shrinking may reach. */
    memset(zd_dict, 0, capacity);
    memcpy(zd_dict + capacity - contentSize, zd_content, (size_t)contentSize);
    zd_quiet();
    s = COVER_selectDict(zd_dict + capacity - contentSize, capacity, (size_t)contentSize, input,
                         zd_sizes, (unsigned)nbFinalize, nbCheck, (size_t)n, p, offsets, 0);
    zd_loud();
    if (COVER_dictSelectionIsError(s)) {
        if (ZSTD_isError(s.totalCompressedSize)) answer_error(s.totalCompressedSize);
        else puts("err 64");
        return;
    }
    memcpy(zd_dict, s.dictContent, s.dictSize);
    snprintf(tail, sizeof(tail), "ok %u ", (unsigned)s.totalCompressedSize);
    line_reset();
    line_append(tail, strlen(tail));
    line_append_hex(zd_dict, s.dictSize);
    puts(line_out);
    COVER_dictSelectionFree(s);
}

static void zdheader(char** args, int nargs)
{
    size_t r;
    long n;
    if (nargs != 1 || (n = parse_hex(args[0])) < 0) { puts("bad"); return; }
    r = ZDICT_getDictHeaderSize(input, (size_t)n);
    if (ZDICT_isError(r)) { answer_error(r); return; }
    printf("ok %u\n", (unsigned)r);
}

static void zdepochs(char** args, int nargs)
{
    COVER_epoch_info_t e;
    if (nargs != 4) { puts("bad"); return; }
    e = COVER_computeEpochs((U32)strtoul(args[0], NULL, 10), (U32)strtoul(args[1], NULL, 10),
                            (U32)strtoul(args[2], NULL, 10), (U32)strtoul(args[3], NULL, 10));
    printf("ok %u %u\n", e.num, e.size);
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
        else if (!strcmp(command, "stream")) stream(args, nargs);
        else if (!strcmp(command, "hist")) hist(args, nargs);
        else if (!strcmp(command, "fseoptlog")) fseoptlog(args, nargs);
        else if (!strcmp(command, "fsenorm")) fsenorm(args, nargs);
        else if (!strcmp(command, "fsencount")) fsencount(args, nargs);
        else if (!strcmp(command, "fsectable")) fsectable(args, nargs);
        else if (!strcmp(command, "fsectablerle")) fsectablerle(args, nargs);
        else if (!strcmp(command, "fsecompress")) fsecompress(args, nargs);
        else if (!strcmp(command, "bitc")) bitc(args, nargs);
        else if (!strcmp(command, "hufctable")) hufctable(args, nargs);
        else if (!strcmp(command, "hufoptlog")) hufoptlog(args, nargs);
        else if (!strcmp(command, "hufcompress")) hufcompress(args, nargs);
        else if (!strcmp(command, "hufreadctable")) hufreadctable(args, nargs);
        else if (!strcmp(command, "seqreset")) seqreset(nargs);
        else if (!strcmp(command, "compress")) compress(args, nargs);
        else if (!strcmp(command, "cstream")) cstream(args, nargs);
        else if (!strcmp(command, "zstdmt")) zstdmt();
        else if (!strcmp(command, "seqblock")) seqblock(args, nargs);
        else if (!strcmp(command, "zdcover")) zdtrain(args, nargs, 0, 0);
        else if (!strcmp(command, "zdcoveropt")) zdtrain(args, nargs, 0, 1);
        else if (!strcmp(command, "zdfast")) zdtrain(args, nargs, 1, 0);
        else if (!strcmp(command, "zdfastopt")) zdtrain(args, nargs, 1, 1);
        else if (!strcmp(command, "zdfinalize")) zdfinalize(args, nargs);
        else if (!strcmp(command, "zdadd")) zdadd(args, nargs);
        else if (!strcmp(command, "zdentropy")) zdentropy(args, nargs);
        else if (!strcmp(command, "zdselect")) zdselect(args, nargs);
        else if (!strcmp(command, "zdheader")) zdheader(args, nargs);
        else if (!strcmp(command, "zdepochs")) zdepochs(args, nargs);
        else puts("bad");
        fflush(stdout);
    }
    return 0;
}
