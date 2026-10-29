/*
 * The libzip side of hivepack-zip's comparison tests.
 *
 * It reads one request per line on stdin and answers each on one line of
 * stdout, by calling libzip 1.12.1. The Rust tests ask the port the same
 * questions and compare the answers as text. scripts/testdata.py builds it
 * from the libzip, zlib and nettle release sources, with config.h, zipconf.h
 * and the part of GnuTLS libzip's crypto backend uses (gnutls/) from this
 * folder. Times are in UTC: the oracle sets TZ, as libzip turns MS-DOS
 * times into time_t with mktime.
 *
 * The random bytes libzip encrypts with (zip_secure_random, through
 * gnutls_rnd) come from a stream the oracle restarts before each
 * zip_close, from the FNV-1a hash of the request's <ops>: a byte is the top
 * byte of x after x = x * 6364136223846793005 + 1442695040888963407, x
 * starting at the hash. Temporary file names take their random numbers
 * apart, from rand().
 *
 * Byte strings are hexadecimal, and "-" is an empty one. An error is
 * "e<zip error>/<system error>". errno is cleared before each request,
 * and in edit requests before each edit, each entry's answers and
 * zip_close: libzip gives it, stale, with some errors (ZIP_ER_SEEK when a
 * local header's extra fields cannot be reached), where the port gives 0.
 *
 *   open <flags> <source> <hex>
 *       zip_open_from_source with <flags> | ZIP_RDONLY, on <hex> as a buffer
 *       source (<source> "b") or a file source (<source> "f", a temporary
 *       file). Answered with the error, or "ok <entries> <torrentzip>
 *       <comment> <raw comment>", then for each entry " |" and:
 *         <name> <raw name> <strict name>        zip_get_name with 0,
 *                                                ZIP_FL_ENC_RAW and
 *                                                ZIP_FL_ENC_STRICT, up to
 *                                                its NUL, as C sees it
 *         <valid>/<size>/<comp_size>/<mtime>/<crc>/<comp_method>/<encryption>
 *                                                zip_stat_index
 *         <opsys>/<attributes>                   zip_file_get_external_attributes
 *         <comment> <raw comment>                zip_file_get_comment
 *         c<count>:<id>=<data>,...               the central extra fields
 *         l<count>:<id>=<data>,...               the local ones, or an error
 *         o<offset>                              _zip_file_get_offset
 *         n<index>,<nocase>,<nodir>,<raw>        zip_name_locate of the name
 *                                                with 0, ZIP_FL_NOCASE, and
 *                                                of its last part with
 *                                                ZIP_FL_NODIR, and of the raw
 *                                                name with ZIP_FL_ENC_RAW
 *
 *   read <flags> <source> <fflags> <chunks> <limit> <hex>
 *       Opens the archive as open does, then reads every entry: zip_fopen_index
 *       with <fflags>, zip_fread in pieces of the comma-separated <chunks>
 *       sizes, taken in turn, until it returns 0 or fails, or <limit> bytes
 *       are read (unless <limit> is -1), then zip_fclose. Answered with the
 *       error of opening the archive, or "ok <entries>", then for each entry
 *       " |" and the error of zip_fopen_index, or
 *       "<bytes>/<hash of the data>/<reads>/<hash of what each returned>/
 *       <end>/<zip_fclose>": <end> is "eof", "limit" or the error, and the
 *       hashes are FNV-1a, the second of the returns written in decimal, each
 *       followed by a comma.
 *
 *   decrypt <flags> <source> <how> <password> <fflags> <chunks> <limit> <hex>
 *       As read, with a password, which <how> gives: "n" none, "d" set
 *       with zip_set_default_password and entries opened with
 *       zip_fopen_index, "e" given to zip_fopen_index_encrypted, "x" set
 *       as the default and an empty one given to zip_fopen_index_encrypted.
 *       The password is a C string, so it ends at a NUL byte in <password>.
 *
 *   range <flags> <source> <start> <len> <hex>
 *       Opens the archive as open does, then reads part of every entry, as
 *       ziptool's cat_partial does: zip_source_zip_file_create with <start>
 *       and <len> (-1 for the rest), zip_source_open, zip_source_read in
 *       pieces of 8192 until it returns 0 or fails, zip_source_close.
 *       Answered "ok <entries>", then for each entry " |" and the error of
 *       creating or opening the source, or "<bytes>/<hash>/<end>/<close>",
 *       <end> "eof" or the error of reading, <close> "0" or the error of
 *       closing, "-" if reading failed (cat_partial does not close then).
 *
 *   edit <flags> <ops> <hex>
 *       zip_open_from_source with <flags> on <hex> in a temporary file, so
 *       that zip_close writes it, then the comma-separated <ops> ("-" for
 *       none), then zip_close. The ops, with <i> an index, byte strings in
 *       hexadecimal and numbers in decimal:
 *         d<i>                      zip_delete
 *         r<i>:<name>:<flags>       zip_file_rename
 *         c<i>:<comment>:<flags>    zip_file_set_comment
 *         a<comment>                zip_set_archive_comment
 *         t<i>:<time>:<date>        zip_file_set_dostime
 *         m<i>:<mtime>              zip_file_set_mtime
 *         x<i>:<opsys>:<attributes> zip_file_set_external_attributes
 *         u<i>                      zip_unchange
 *         U                         zip_unchange_all
 *         A                         zip_unchange_archive
 *         f<flag>:<value>           zip_set_archive_flag
 *         e<i>:<id>:<idx>:<data>:<flags>  zip_file_extra_field_set
 *         E<i>:<id>:<idx>:<flags>   zip_file_extra_field_delete_by_id
 *         D<i>:<idx>:<flags>        zip_file_extra_field_delete
 *         +<name>:<flags>:<mtime>:<data>:<kind>  zip_file_add, from a
 *                                   source of <data> with <mtime>, its size
 *                                   known (<kind> "s") or not ("u")
 *         R<i>:<mtime>:<data>:<kind> zip_file_replace, from the same
 *         N<name>:<flags>:<time>:<date>  zip_dir_add, then
 *                                   zip_file_set_dostime of the directory,
 *                                   as its buffer source has the time now
 *         z<i>:<method>:<flags>     zip_set_file_compression
 *         y<i>:<method>:<password>  zip_file_set_encryption, the password
 *                                   NULL if "-"
 *         P<password>               zip_set_default_password, NULL if "-"
 *       An add answers with the index of the entry, others with 0.
 *       Answered with the error of opening, or "ok", each op's result (" 0"
 *       or " " and the error), " |" and the archive comment with 0 and
 *       ZIP_FL_UNCHANGED, then for each entry " |" and "<name>/<name as
 *       read>/<comment>/<opsys>:<attributes>/<mtime>/<index of the
 *       name>/c<central extra fields>/l<local ones>", each an error if it
 *       fails, the extra fields as open has them, then " |" and the error of zip_close,
 *       or "unchanged" (the file was not written), "removed" or "written
 *       <hex>" with the file written.
 *
 *   editb <flags> <fragment> <ops> <hex>
 *       As edit, on a buffer source of <hex> in fragments of <fragment>
 *       bytes (one if 0), as ziptool's -m and -F make it, which can clone
 *       what zip_close keeps. After zip_close, " |" and "deleted" if the
 *       buffer was removed, or "buffer <hex>" with what it holds.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include "zipint.h"

static int digit(char c) {
    return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10;
}

/* Not with sscanf, which takes the length of the rest of the text each
 * time. */
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
        bytes[i] = (unsigned char)(digit(text[2 * i]) << 4 | digit(text[2 * i + 1]));
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

static unsigned long long fnv64(unsigned long long hash, const unsigned char *bytes, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 0x00000100000001b3ULL;
    }
    return hash;
}

static unsigned long long random_state;

int gnutls_rnd(int level, void *data, size_t len) {
    unsigned char *bytes = data;
    size_t i;
    (void)level;
    for (i = 0; i < len; i++) {
        random_state = random_state * 6364136223846793005ULL + 1442695040888963407ULL;
        bytes[i] = (unsigned char)(random_state >> 56);
    }
    return 0;
}

zip_uint32_t zip_random_uint32(void) {
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned)getpid() ^ (unsigned)time(NULL));
        seeded = 1;
    }
    return (zip_uint32_t)rand() << 16 ^ (zip_uint32_t)rand();
}

/* A password in hexadecimal as a C string, or NULL for "-" if dash_null. */
static char *password_of(const char *hex, int dash_null) {
    size_t len;
    unsigned char *bytes;
    if (dash_null && strcmp(hex, "-") == 0)
        return NULL;
    bytes = unhex(hex, &len);
    bytes[len] = '\0';
    return (char *)bytes;
}

static void put_error(const zip_error_t *error) {
    printf("e%d/%d", zip_error_code_zip(error), zip_error_code_system(error));
}

static void put_name(zip_t *za, zip_uint64_t i, zip_flags_t flags) {
    const char *name = zip_get_name(za, i, flags);
    if (name)
        put_hex((const unsigned char *)name, strlen(name));
    else
        put_error(zip_get_error(za));
}

static void put_comment(zip_t *za, zip_uint64_t i, zip_flags_t flags) {
    zip_uint32_t len;
    const char *comment = zip_file_get_comment(za, i, &len, flags);
    if (comment)
        put_hex((const unsigned char *)comment, len);
    else
        put_error(zip_get_error(za));
}

static void put_extra_fields(zip_t *za, zip_uint64_t i, zip_flags_t flags) {
    zip_int16_t count = zip_file_extra_fields_count(za, i, flags);
    zip_int16_t j;
    if (count < 0) {
        put_error(zip_get_error(za));
        return;
    }
    printf("%d:", count);
    for (j = 0; j < count; j++) {
        zip_uint16_t id, len;
        const zip_uint8_t *data = zip_file_extra_field_get(za, i, (zip_uint16_t)j, &id, &len, flags);
        if (j > 0)
            putchar(',');
        if (data) {
            printf("%u=", id);
            put_hex(data, len);
        }
        else {
            put_error(zip_get_error(za));
        }
    }
}

static void put_locate(zip_t *za, const char *name, zip_flags_t flags) {
    zip_int64_t index = zip_name_locate(za, name, flags);
    if (index >= 0)
        printf("%lld", (long long)index);
    else
        put_error(zip_get_error(za));
}

/* Opens <hex> as an archive with <flags> | ZIP_RDONLY, from a buffer or a
 * temporary file; NULL with the error printed if libzip refuses it. */
static zip_t *open_archive(int flags, const char *kind, unsigned char *data, size_t len, char *path,
                           int *made_file) {
    zip_error_t error;
    zip_source_t *src;
    zip_t *za;

    zip_error_init(&error);
    if (strcmp(kind, "f") == 0) {
        int fd = mkstemp(path);
        if (fd < 0 || write(fd, data, len) != (ssize_t)len) {
            puts("bad");
            return NULL;
        }
        close(fd);
        *made_file = 1;
        src = zip_source_file_create(path, 0, -1, &error);
    }
    else {
        src = zip_source_buffer_create(data, len, 0, &error);
    }
    if (src == NULL) {
        put_error(&error);
        putchar('\n');
        zip_error_fini(&error);
        return NULL;
    }
    za = zip_open_from_source(src, flags | ZIP_RDONLY, &error);
    if (za == NULL) {
        zip_source_free(src);
        put_error(&error);
        putchar('\n');
    }
    zip_error_fini(&error);
    return za;
}

static void do_read(int flags, const char *kind, char how, const char *password_hex, int fflags,
                    const char *chunks, long long limit, const char *data_hex) {
    size_t len;
    unsigned char *data = unhex(data_hex, &len);
    char path[] = "/tmp/zip-oracle-XXXXXX";
    int made_file = 0;
    zip_t *za = open_archive(flags, kind, data, len, path, &made_file);
    zip_uint64_t i, n;
    unsigned char *buffer = malloc(1 << 20);
    char *password = password_of(password_hex, 0);

    if (za == NULL)
        goto done;
    if (how == 'd' || how == 'x')
        zip_set_default_password(za, password);
    n = (zip_uint64_t)zip_get_num_entries(za, 0);
    printf("ok %llu", (unsigned long long)n);
    for (i = 0; i < n; i++) {
        zip_file_t *zf = how == 'e'   ? zip_fopen_index_encrypted(za, i, (zip_flags_t)fflags, password)
                         : how == 'x' ? zip_fopen_index_encrypted(za, i, (zip_flags_t)fflags, "")
                                      : zip_fopen_index(za, i, (zip_flags_t)fflags);
        unsigned long long data_hash = 0xcbf29ce484222325ULL, returns_hash = 0xcbf29ce484222325ULL;
        long long total = 0, reads = 0;
        const char *chunk = chunks;
        const char *end = "eof";
        zip_error_t read_error;
        int failed = 0;

        printf(" |");
        if (zf == NULL) {
            put_error(zip_get_error(za));
            continue;
        }
        for (;;) {
            char text[32];
            zip_int64_t got;
            long long want = strtoll(chunk, NULL, 10);
            chunk = strchr(chunk, ',') ? strchr(chunk, ',') + 1 : chunks;
            if (limit >= 0 && want > limit - total)
                want = limit - total;
            if (limit >= 0 && want == 0) {
                end = "limit";
                break;
            }
            got = zip_fread(zf, buffer, (zip_uint64_t)want);
            reads++;
            snprintf(text, sizeof(text), "%lld,", (long long)got);
            returns_hash = fnv64(returns_hash, (const unsigned char *)text, strlen(text));
            if (got < 0) {
                zip_error_init(&read_error);
                zip_error_set(&read_error, zip_error_code_zip(zip_file_get_error(zf)),
                              zip_error_code_system(zip_file_get_error(zf)));
                failed = 1;
                break;
            }
            if (got == 0)
                break;
            data_hash = fnv64(data_hash, buffer, (size_t)got);
            total += got;
        }
        printf("%lld/%016llx/%lld/%016llx/", total, data_hash, reads, returns_hash);
        if (failed)
            put_error(&read_error);
        else
            fputs(end, stdout);
        printf("/%d", zip_fclose(zf));
    }
    putchar('\n');
    zip_discard(za);

done:
    if (made_file)
        unlink(path);
    free(password);
    free(buffer);
    free(data);
}

static void do_range(int flags, const char *kind, unsigned long long start, long long rlen,
                     const char *data_hex) {
    size_t len;
    unsigned char *data = unhex(data_hex, &len);
    char path[] = "/tmp/zip-oracle-XXXXXX";
    int made_file = 0;
    zip_t *za = open_archive(flags, kind, data, len, path, &made_file);
    zip_uint64_t i, n;
    unsigned char buffer[8192];

    if (za == NULL)
        goto done;
    n = (zip_uint64_t)zip_get_num_entries(za, 0);
    printf("ok %llu", (unsigned long long)n);
    for (i = 0; i < n; i++) {
        zip_error_t error;
        zip_source_t *src;
        zip_int64_t got;
        unsigned long long hash = 0xcbf29ce484222325ULL, total = 0;

        printf(" |");
        zip_error_init(&error);
        src = zip_source_zip_file_create(za, i, 0, start, rlen, NULL, &error);
        if (src == NULL) {
            put_error(&error);
            continue;
        }
        if (zip_source_open(src) < 0) {
            put_error(zip_source_error(src));
            zip_source_free(src);
            continue;
        }
        while ((got = zip_source_read(src, buffer, sizeof(buffer))) > 0) {
            hash = fnv64(hash, buffer, (size_t)got);
            total += (unsigned long long)got;
        }
        printf("%llu/%016llx/", total, hash);
        if (got < 0) {
            put_error(zip_source_error(src));
            fputs("/-", stdout);
        }
        else {
            fputs("eof/", stdout);
            if (zip_source_close(src) < 0)
                put_error(zip_source_error(src));
            else
                putchar('0');
        }
        zip_source_free(src);
    }
    putchar('\n');
    zip_discard(za);

done:
    if (made_file)
        unlink(path);
    free(data);
}

/* A source of data in memory, with a fixed modification time, and its size
 * known or not. */
struct memory_source {
    unsigned char *data;
    zip_uint64_t len;
    zip_uint64_t offset;
    time_t mtime;
    int known_size;
    zip_error_t error;
};

static zip_int64_t memory_callback(void *ud, void *data, zip_uint64_t len, zip_source_cmd_t cmd) {
    struct memory_source *m = ud;
    switch (cmd) {
    case ZIP_SOURCE_OPEN:
        m->offset = 0;
        return 0;
    case ZIP_SOURCE_READ: {
        zip_uint64_t n = ZIP_MIN(len, m->len - m->offset);
        memcpy(data, m->data + m->offset, n);
        m->offset += n;
        return (zip_int64_t)n;
    }
    case ZIP_SOURCE_CLOSE:
        return 0;
    case ZIP_SOURCE_STAT: {
        zip_stat_t *st = data;
        zip_stat_init(st);
        st->mtime = m->mtime;
        st->valid = ZIP_STAT_MTIME;
        if (m->known_size) {
            st->size = m->len;
            st->comp_size = m->len;
            st->comp_method = ZIP_CM_STORE;
            st->encryption_method = ZIP_EM_NONE;
            st->valid |= ZIP_STAT_SIZE | ZIP_STAT_COMP_SIZE | ZIP_STAT_COMP_METHOD | ZIP_STAT_ENCRYPTION_METHOD;
        }
        return sizeof(*st);
    }
    case ZIP_SOURCE_ERROR:
        return zip_error_to_data(&m->error, data, len);
    case ZIP_SOURCE_FREE:
        free(m->data);
        free(m);
        return 0;
    case ZIP_SOURCE_SEEK: {
        zip_int64_t new_offset = zip_source_seek_compute_offset(m->offset, m->len, data, len, &m->error);
        if (new_offset < 0)
            return -1;
        m->offset = (zip_uint64_t)new_offset;
        return 0;
    }
    case ZIP_SOURCE_TELL:
        return (zip_int64_t)m->offset;
    case ZIP_SOURCE_SUPPORTS:
        return zip_source_make_command_bitmap(ZIP_SOURCE_OPEN, ZIP_SOURCE_READ, ZIP_SOURCE_CLOSE, ZIP_SOURCE_STAT,
                                              ZIP_SOURCE_ERROR, ZIP_SOURCE_FREE, ZIP_SOURCE_SEEK, ZIP_SOURCE_TELL,
                                              ZIP_SOURCE_SUPPORTS_REOPEN, -1);
    default:
        zip_error_set(&m->error, ZIP_ER_OPNOTSUPP, 0);
        return -1;
    }
}

static zip_source_t *memory_source(zip_t *za, const char *mtime, const char *data_hex, const char *kind) {
    struct memory_source *m = malloc(sizeof(*m));
    zip_source_t *src;
    size_t len;
    m->data = unhex(data_hex, &len);
    m->len = len;
    m->offset = 0;
    m->mtime = (time_t)strtoll(mtime, NULL, 10);
    m->known_size = strcmp(kind, "u") != 0;
    zip_error_init(&m->error);
    if ((src = zip_source_function(za, memory_callback, m)) == NULL) {
        free(m->data);
        free(m);
    }
    return src;
}

/* Applies one op of an edit request; its result, 0 or -1, or for an add
 * the index. */
static int edit_op(zip_t *za, char *op) {
    char *rest = op + 1;
    char *fields[5] = {rest, NULL, NULL, NULL, NULL};
    int count = 1;
    char *colon;
    while (count < 5 && (colon = strchr(fields[count - 1], ':')) != NULL) {
        *colon = '\0';
        fields[count++] = colon + 1;
    }
    switch (op[0]) {
    case 'd':
        return zip_delete(za, strtoull(fields[0], NULL, 10));
    case 'r': {
        size_t len;
        unsigned char *name = unhex(fields[1], &len);
        int ret;
        name[len] = '\0';
        ret = zip_file_rename(za, strtoull(fields[0], NULL, 10), (const char *)name,
                              (zip_flags_t)strtoul(fields[2], NULL, 10));
        free(name);
        return ret;
    }
    case 'c': {
        size_t len;
        unsigned char *comment = unhex(fields[1], &len);
        int ret = zip_file_set_comment(za, strtoull(fields[0], NULL, 10), (const char *)comment,
                                       (zip_uint16_t)len, (zip_flags_t)strtoul(fields[2], NULL, 10));
        free(comment);
        return ret;
    }
    case 'a': {
        size_t len;
        unsigned char *comment = unhex(fields[0], &len);
        int ret = zip_set_archive_comment(za, (const char *)comment, (zip_uint16_t)len);
        free(comment);
        return ret;
    }
    case 't':
        return zip_file_set_dostime(za, strtoull(fields[0], NULL, 10), (zip_uint16_t)atoi(fields[1]),
                                    (zip_uint16_t)atoi(fields[2]), 0);
    case 'm':
        return zip_file_set_mtime(za, strtoull(fields[0], NULL, 10), (time_t)strtoll(fields[1], NULL, 10), 0);
    case 'x':
        return zip_file_set_external_attributes(za, strtoull(fields[0], NULL, 10), 0,
                                                (zip_uint8_t)atoi(fields[1]),
                                                (zip_uint32_t)strtoul(fields[2], NULL, 10));
    case 'u':
        return zip_unchange(za, strtoull(fields[0], NULL, 10));
    case 'U':
        return zip_unchange_all(za);
    case 'A':
        return zip_unchange_archive(za);
    case 'f':
        return zip_set_archive_flag(za, (zip_flags_t)strtoul(fields[0], NULL, 10), atoi(fields[1]));
    case 'e': {
        size_t len;
        unsigned char *data = unhex(fields[3], &len);
        int ret = zip_file_extra_field_set(za, strtoull(fields[0], NULL, 10), (zip_uint16_t)atoi(fields[1]),
                                           (zip_uint16_t)atoi(fields[2]), data, (zip_uint16_t)len,
                                           (zip_flags_t)strtoul(fields[4], NULL, 10));
        free(data);
        return ret;
    }
    case 'E':
        return zip_file_extra_field_delete_by_id(za, strtoull(fields[0], NULL, 10), (zip_uint16_t)atoi(fields[1]),
                                                 (zip_uint16_t)atoi(fields[2]), (zip_flags_t)strtoul(fields[3], NULL, 10));
    case 'D':
        return zip_file_extra_field_delete(za, strtoull(fields[0], NULL, 10), (zip_uint16_t)atoi(fields[1]),
                                           (zip_flags_t)strtoul(fields[2], NULL, 10));
    case '+': {
        size_t len;
        unsigned char *name = unhex(fields[0], &len);
        zip_source_t *src = memory_source(za, fields[2], fields[3], fields[4]);
        zip_int64_t idx;
        name[len] = '\0';
        if (src == NULL) {
            free(name);
            return -1;
        }
        if ((idx = zip_file_add(za, (const char *)name, src, (zip_flags_t)strtoul(fields[1], NULL, 10))) < 0)
            zip_source_free(src);
        free(name);
        return idx < 0 ? -1 : (int)idx;
    }
    case 'R': {
        zip_source_t *src = memory_source(za, fields[1], fields[2], fields[3]);
        int ret;
        if (src == NULL)
            return -1;
        if ((ret = zip_file_replace(za, strtoull(fields[0], NULL, 10), src, 0)) < 0)
            zip_source_free(src);
        return ret;
    }
    case 'N': {
        size_t len;
        unsigned char *name = unhex(fields[0], &len);
        zip_int64_t idx;
        name[len] = '\0';
        idx = zip_dir_add(za, (const char *)name, (zip_flags_t)strtoul(fields[1], NULL, 10));
        free(name);
        if (idx < 0)
            return -1;
        if (zip_file_set_dostime(za, (zip_uint64_t)idx, (zip_uint16_t)atoi(fields[2]), (zip_uint16_t)atoi(fields[3]), 0) < 0)
            return -1;
        return (int)idx;
    }
    case 'z':
        return zip_set_file_compression(za, strtoull(fields[0], NULL, 10), (zip_int32_t)strtol(fields[1], NULL, 10),
                                        (zip_uint32_t)strtoul(fields[2], NULL, 10));
    case 'y': {
        char *password = password_of(fields[2], 1);
        int ret = zip_file_set_encryption(za, strtoull(fields[0], NULL, 10), (zip_uint16_t)strtoul(fields[1], NULL, 10),
                                          password);
        free(password);
        return ret;
    }
    case 'P': {
        char *password = password_of(fields[0], 1);
        int ret = zip_set_default_password(za, password);
        free(password);
        return ret;
    }
    default:
        return -2;
    }
}

/* A buffer source of data in fragments of fragment_size bytes, or one. */
static zip_source_t *fragment_source(unsigned char *data, size_t len, size_t fragment_size, zip_buffer_fragment_t **fragmentsp,
                                     zip_error_t *error) {
    zip_uint64_t nfragments, i;
    zip_buffer_fragment_t *fragments;

    if (fragment_size == 0 || len == 0)
        return zip_source_buffer_create(len ? data : NULL, len, 0, error);
    nfragments = (len + fragment_size - 1) / fragment_size;
    fragments = malloc(sizeof(fragments[0]) * nfragments);
    for (i = 0; i < nfragments; i++) {
        fragments[i].data = data + i * fragment_size;
        fragments[i].length = ZIP_MIN(fragment_size, len - i * fragment_size);
    }
    *fragmentsp = fragments;
    return zip_source_buffer_fragment_create(fragments, nfragments, 0, error);
}

/* An edit request, on a file if fragment is -1, else on a buffer. */
static void do_edit(int flags, long long fragment, char *ops, const char *data_hex) {
    size_t len;
    unsigned char *data = unhex(data_hex, &len);
    char path[] = "/tmp/zip-oracle-XXXXXX";
    zip_buffer_fragment_t *fragments = NULL;
    zip_error_t error;
    zip_source_t *src;
    zip_t *za;
    zip_uint64_t i, n;
    struct stat before, after;
    int comment_len;
    const char *comment;
    char *op;
    int made_file = 0;
    unsigned long long seed = fnv64(0xcbf29ce484222325ULL, (const unsigned char *)ops, strlen(ops));

    zip_error_init(&error);
    if (fragment < 0) {
        int fd = mkstemp(path);
        if (fd < 0 || write(fd, data, len) != (ssize_t)len) {
            puts("bad");
            free(data);
            return;
        }
        close(fd);
        made_file = 1;
        stat(path, &before);
        src = zip_source_file_create(path, 0, -1, &error);
    }
    else {
        src = fragment_source(data, len, (size_t)fragment, &fragments, &error);
    }
    if (src == NULL) {
        put_error(&error);
        putchar('\n');
        goto done;
    }
    zip_source_keep(src);
    if ((za = zip_open_from_source(src, flags, &error)) == NULL) {
        zip_source_free(src);
        zip_source_free(src);
        put_error(&error);
        putchar('\n');
        goto done;
    }

    fputs("ok", stdout);
    if (strcmp(ops, "-") != 0) {
        for (op = strtok(ops, ","); op; op = strtok(NULL, ",")) {
            int ret;
            errno = 0;
            ret = edit_op(za, op);
            putchar(' ');
            if (ret >= 0)
                printf("%d", ret);
            else if (ret == -2)
                fputs("bad", stdout);
            else
                put_error(zip_get_error(za));
        }
    }

    fputs(" |", stdout);
    comment = zip_get_archive_comment(za, &comment_len, 0);
    put_hex((const unsigned char *)comment, (size_t)comment_len);
    putchar(' ');
    comment = zip_get_archive_comment(za, &comment_len, ZIP_FL_UNCHANGED);
    put_hex((const unsigned char *)comment, (size_t)comment_len);

    n = (zip_uint64_t)zip_get_num_entries(za, 0);
    for (i = 0; i < n; i++) {
        zip_stat_t st;
        zip_uint8_t opsys;
        zip_uint32_t attributes;
        const char *name;

        fputs(" |", stdout);
        errno = 0;
        put_name(za, i, 0);
        putchar('/');
        put_name(za, i, ZIP_FL_UNCHANGED);
        putchar('/');
        put_comment(za, i, 0);
        putchar('/');
        if (zip_file_get_external_attributes(za, i, 0, &opsys, &attributes) == 0)
            printf("%u:%u", opsys, attributes);
        else
            put_error(zip_get_error(za));
        putchar('/');
        if (zip_stat_index(za, i, 0, &st) == 0)
            printf("%lld", (long long)st.mtime);
        else
            put_error(zip_get_error(za));
        putchar('/');
        if ((name = zip_get_name(za, i, 0)) != NULL)
            put_locate(za, name, 0);
        else
            put_error(zip_get_error(za));
        fputs("/c", stdout);
        put_extra_fields(za, i, ZIP_FL_CENTRAL);
        fputs("/l", stdout);
        put_extra_fields(za, i, ZIP_FL_LOCAL);
    }

    fputs(" |", stdout);
    errno = 0;
    random_state = seed;
    if (zip_close(za) < 0) {
        put_error(zip_get_error(za));
        zip_discard(za);
    }
    else if (fragment >= 0) {
        zip_stat_t st;
        zip_stat_init(&st);
        if (zip_source_open(src) < 0) {
            if (zip_error_code_zip(zip_source_error(src)) == ZIP_ER_DELETED)
                fputs("deleted", stdout);
            else
                put_error(zip_source_error(src));
        }
        else {
            unsigned char buffer[8192];
            zip_int64_t got, total = 0;
            fputs("buffer ", stdout);
            while ((got = zip_source_read(src, buffer, sizeof(buffer))) > 0) {
                zip_int64_t k;
                for (k = 0; k < got; k++)
                    printf("%02x", buffer[k]);
                total += got;
            }
            if (total == 0)
                putchar('-');
            zip_source_close(src);
        }
    }
    else if (stat(path, &after) < 0) {
        fputs("removed", stdout);
    }
    else if (after.st_ino == before.st_ino) {
        fputs("unchanged", stdout);
    }
    else {
        FILE *f = fopen(path, "rb");
        unsigned char buffer[8192];
        size_t got, total = 0;
        fputs("written ", stdout);
        while ((got = fread(buffer, 1, sizeof(buffer), f)) > 0) {
            size_t k;
            for (k = 0; k < got; k++)
                printf("%02x", buffer[k]);
            total += got;
        }
        if (total == 0)
            putchar('-');
        fclose(f);
    }
    putchar('\n');

    zip_source_free(src);

done:
    zip_error_fini(&error);
    if (made_file)
        unlink(path);
    free(fragments);
    free(data);
}

static void do_open(int flags, const char *kind, const char *data_hex) {
    size_t len;
    unsigned char *data = unhex(data_hex, &len);
    char path[] = "/tmp/zip-oracle-XXXXXX";
    int made_file = 0;
    zip_error_t error;
    zip_source_t *src;
    zip_t *za;
    zip_uint64_t i, n;
    int comment_len;
    const char *comment;

    zip_error_init(&error);
    if (strcmp(kind, "f") == 0) {
        int fd = mkstemp(path);
        if (fd < 0 || write(fd, data, len) != (ssize_t)len) {
            puts("bad");
            free(data);
            return;
        }
        close(fd);
        made_file = 1;
        src = zip_source_file_create(path, 0, -1, &error);
    }
    else {
        src = zip_source_buffer_create(data, len, 0, &error);
    }
    if (src == NULL) {
        put_error(&error);
        putchar('\n');
        goto done;
    }

    za = zip_open_from_source(src, flags | ZIP_RDONLY, &error);
    if (za == NULL) {
        zip_source_free(src);
        put_error(&error);
        putchar('\n');
        goto done;
    }

    n = (zip_uint64_t)zip_get_num_entries(za, 0);
    printf("ok %llu %d ", (unsigned long long)n, zip_get_archive_flag(za, ZIP_AFL_IS_TORRENTZIP, 0));
    comment = zip_get_archive_comment(za, &comment_len, 0);
    put_hex((const unsigned char *)comment, (size_t)comment_len);
    putchar(' ');
    comment = zip_get_archive_comment(za, &comment_len, ZIP_FL_ENC_RAW);
    put_hex((const unsigned char *)comment, (size_t)comment_len);

    for (i = 0; i < n; i++) {
        zip_stat_t st;
        zip_uint8_t opsys;
        zip_uint32_t attributes;
        zip_error_t offset_error;
        zip_uint64_t offset;
        const char *name;

        printf(" |");
        put_name(za, i, 0);
        putchar(' ');
        put_name(za, i, ZIP_FL_ENC_RAW);
        putchar(' ');
        put_name(za, i, ZIP_FL_ENC_STRICT);
        putchar(' ');
        if (zip_stat_index(za, i, 0, &st) == 0)
            printf("%llu/%llu/%llu/%lld/%u/%u/%u", (unsigned long long)st.valid, (unsigned long long)st.size,
                   (unsigned long long)st.comp_size, (long long)st.mtime, st.crc, st.comp_method,
                   st.encryption_method);
        else
            put_error(zip_get_error(za));
        putchar(' ');
        if (zip_file_get_external_attributes(za, i, 0, &opsys, &attributes) == 0)
            printf("%u/%u", opsys, attributes);
        else
            put_error(zip_get_error(za));
        putchar(' ');
        put_comment(za, i, 0);
        putchar(' ');
        put_comment(za, i, ZIP_FL_ENC_RAW);
        printf(" c");
        put_extra_fields(za, i, ZIP_FL_CENTRAL);
        printf(" l");
        put_extra_fields(za, i, ZIP_FL_LOCAL);
        printf(" o");
        zip_error_init(&offset_error);
        offset = _zip_file_get_offset(za, i, &offset_error);
        if (offset == 0)
            put_error(&offset_error);
        else
            printf("%llu", (unsigned long long)offset);
        printf(" n");
        name = zip_get_name(za, i, 0);
        if (name) {
            const char *last = strrchr(name, '/');
            put_locate(za, name, 0);
            putchar(',');
            put_locate(za, name, ZIP_FL_NOCASE);
            putchar(',');
            put_locate(za, last ? last + 1 : name, ZIP_FL_NODIR);
            putchar(',');
            put_locate(za, zip_get_name(za, i, ZIP_FL_ENC_RAW), ZIP_FL_ENC_RAW);
        }
        else {
            putchar('-');
        }
    }
    putchar('\n');
    zip_discard(za);

done:
    zip_error_fini(&error);
    if (made_file)
        unlink(path);
    free(data);
}

int main(void) {
    size_t cap = 1 << 20;
    char *line = malloc(cap);

    setenv("TZ", "UTC", 1);
    tzset();

    while (fgets(line, (int)cap, stdin)) {
        size_t n = strlen(line);
        char *words[9];
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
        for (word = strtok(line, " "); word && count < 9; word = strtok(NULL, " "))
            words[count++] = word;
        errno = 0;
        if (count == 4 && strcmp(words[0], "open") == 0)
            do_open(atoi(words[1]), words[2], words[3]);
        else if (count == 6 && strcmp(words[0], "range") == 0)
            do_range(atoi(words[1]), words[2], strtoull(words[3], NULL, 10), atoll(words[4]), words[5]);
        else if (count == 4 && strcmp(words[0], "edit") == 0)
            do_edit(atoi(words[1]), -1, words[2], words[3]);
        else if (count == 5 && strcmp(words[0], "editb") == 0)
            do_edit(atoi(words[1]), atoll(words[2]), words[3], words[4]);
        else if (count == 7 && strcmp(words[0], "read") == 0)
            do_read(atoi(words[1]), words[2], 'n', "-", atoi(words[3]), words[4], atoll(words[5]), words[6]);
        else if (count == 9 && strcmp(words[0], "decrypt") == 0)
            do_read(atoi(words[1]), words[2], words[3][0], words[4], atoi(words[5]), words[6], atoll(words[7]),
                    words[8]);
        else
            puts("bad");
        fflush(stdout);
    }
    free(line);
    return 0;
}
