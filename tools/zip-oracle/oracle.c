/*
 * The libzip side of hivepack-zip's comparison tests.
 *
 * It reads one request per line on stdin and answers each on one line of
 * stdout, by calling libzip 1.12.1. The Rust tests ask the port the same
 * questions and compare the answers as text. scripts/testdata.py builds it
 * from the libzip and zlib release sources, with config.h and zipconf.h
 * from this folder. Times are in UTC: the oracle sets TZ, as libzip turns
 * MS-DOS times into time_t with mktime.
 *
 * Byte strings are hexadecimal, and "-" is an empty one. An error is
 * "e<zip error>/<system error>".
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "zipint.h"

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
        char *words[4];
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
        for (word = strtok(line, " "); word && count < 4; word = strtok(NULL, " "))
            words[count++] = word;
        if (count == 4 && strcmp(words[0], "open") == 0)
            do_open(atoi(words[1]), words[2], words[3]);
        else
            puts("bad");
        fflush(stdout);
    }
    free(line);
    return 0;
}
