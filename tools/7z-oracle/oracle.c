/* The LZMA SDK's 7z decoder, for comparing hivepack-7z with it: one request
 * a line on stdin, one answer a line on stdout.
 *
 *   archive PATH
 *
 * opens the archive with SzArEx_Open and, if that succeeds, answers
 *
 *   OPEN FILES FOLDERS f... d... x...
 *
 * where OPEN is SzArEx_Open's result, and
 *   f:I:FOLDER:ISDIR:SIZE:CRC:ATTRIB:MTIME:CTIME:NAME  describes file I, a
 *     field being - when not defined, FOLDER - when the file has none, and
 *     NAME the UTF-16 units in hexadecimal, - when empty;
 *   d:FO:RES:HASH  is SzAr_DecodeFolder's result for folder FO and the
 *     FNV-1a hash of what it wrote;
 *   x:I:RES:SIZE:HASH  is SzArEx_Extract's for file I, with the hash of the
 *     file's data. The folder it keeps is forgotten after an error, as what
 *     it holds then is not the folder.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "7z.h"
#include "7zAlloc.h"
#include "7zBuf.h"
#include "7zCrc.h"
#include "7zFile.h"

#define BUF_SIZE ((size_t)1 << 18)

static const ISzAlloc g_alloc = { SzAlloc, SzFree };

static unsigned long long fnv64(const unsigned char *bytes, size_t len) {
    unsigned long long hash = 0xcbf29ce484222325ULL;
    size_t i;
    for (i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

static void print_time(const CSzBitUi64s *t, size_t i) {
    if (SzBitWithVals_Check(t, i))
        printf(":%llu", ((unsigned long long)t->Vals[i].High << 32) | t->Vals[i].Low);
    else
        printf(":-");
}

static void do_archive(const char *path) {
    CFileInStream file;
    CLookToRead2 look;
    CSzArEx db;
    SRes res;
    UInt32 i;
    UInt32 block = 0xFFFFFFFF;
    Byte *out = NULL;
    size_t out_size = 0;

    if (InFile_Open(&file.file, path) != 0) {
        printf("bad\n");
        return;
    }
    FileInStream_CreateVTable(&file);
    file.wres = 0;
    LookToRead2_CreateVTable(&look, False);
    look.buf = (Byte *)malloc(BUF_SIZE);
    look.bufSize = BUF_SIZE;
    look.realStream = &file.vt;
    LookToRead2_INIT(&look)

    SzArEx_Init(&db);
    res = SzArEx_Open(&db, &look.vt, &g_alloc, &g_alloc);
    printf("%d", res);
    if (res != SZ_OK) {
        printf("\n");
        goto end;
    }
    printf(" %u %u", db.NumFiles, db.db.NumFolders);
    for (i = 0; i < db.NumFiles; i++) {
        size_t len = SzArEx_GetFileNameUtf16(&db, i, NULL);
        UInt16 *name = (UInt16 *)malloc((len + 1) * sizeof(UInt16));
        size_t k;
        SzArEx_GetFileNameUtf16(&db, i, name);
        printf(" f:%u", i);
        if (db.FileToFolder[i] == (UInt32)-1)
            printf(":-");
        else
            printf(":%u", db.FileToFolder[i]);
        printf(":%d:%llu", SzArEx_IsDir(&db, i) ? 1 : 0,
               (unsigned long long)SzArEx_GetFileSize(&db, i));
        if (SzBitWithVals_Check(&db.CRCs, i))
            printf(":%08x", db.CRCs.Vals[i]);
        else
            printf(":-");
        if (SzBitWithVals_Check(&db.Attribs, i))
            printf(":%08x", db.Attribs.Vals[i]);
        else
            printf(":-");
        print_time(&db.MTime, i);
        print_time(&db.CTime, i);
        printf(":");
        /* Without the terminating 0. */
        if (len <= 1)
            printf("-");
        for (k = 0; k + 1 < len; k++)
            printf("%04x", name[k]);
        free(name);
    }
    for (i = 0; i < db.db.NumFolders; i++) {
        UInt64 size = SzAr_GetFolderUnpackSize(&db.db, i);
        Byte *buf = (size_t)size == size ? (Byte *)malloc((size_t)size + 1) : NULL;
        if (buf == NULL) {
            printf(" d:%u:%d:-", i, SZ_ERROR_MEM);
            continue;
        }
        res = SzAr_DecodeFolder(&db.db, i, &look.vt, db.dataPos, buf, (size_t)size, &g_alloc);
        if (res == SZ_OK)
            printf(" d:%u:0:%016llx", i, fnv64(buf, (size_t)size));
        else
            printf(" d:%u:%d:-", i, res);
        free(buf);
    }
    for (i = 0; i < db.NumFiles; i++) {
        size_t offset = 0, processed = 0;
        res = SzArEx_Extract(&db, &look.vt, i, &block, &out, &out_size, &offset, &processed,
                             &g_alloc, &g_alloc);
        if (res == SZ_OK) {
            printf(" x:%u:0:%llu:%016llx", i, (unsigned long long)processed,
                   fnv64(out + offset, processed));
        } else {
            printf(" x:%u:%d:-:-", i, res);
            ISzAlloc_Free(&g_alloc, out);
            out = NULL;
            out_size = 0;
            block = 0xFFFFFFFF;
        }
    }
    printf("\n");
end:
    ISzAlloc_Free(&g_alloc, out);
    SzArEx_Free(&db, &g_alloc);
    free(look.buf);
    File_Close(&file.file);
}

int main(void) {
    static char line[1 << 16];
    CrcGenerateTable();
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strncmp(line, "archive ", 8) == 0)
            do_archive(line + 8);
        else
            printf("bad\n");
        fflush(stdout);
    }
    return 0;
}
