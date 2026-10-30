/*
 * The libarchive side of hivepack-iso's comparison tests.
 *
 * It reads one request per line on stdin and answers each on one line of
 * stdout, by calling libarchive 3.8.10, whose ISO 9660 reader hivepack-iso
 * ports. The Rust tests ask the port the same questions and compare the
 * answers as text. scripts/testdata.py builds it from the libarchive and
 * zlib release sources, with config.h.
 *
 * Byte strings are hexadecimal, "-" is an empty one and "~" none at all.
 *
 *   sizes
 *       The sizes of mode_t and dev_t, which libarchive stores an entry's
 *       mode and device number in: "ok <mode_t> <dev_t>".
 *
 *   read <mode> <image>
 *       Every entry of <image>, read with archive_read_support_format_iso9660
 *       alone, and all of its data with archive_read_data_block. <mode> is
 *       three characters: "m" to open the image in memory
 *       (archive_read_open_memory, which can seek) or "s" to give it as one
 *       block through a read callback that cannot; then "1" or "0" for the
 *       "joliet" option and "1" or "0" for "rockridge" (each "0" turns the
 *       extension off). Answered with fields separated by "|": "open", or
 *       "fatal:<message>" alone when the image is not opened; then one
 *       field per entry, and how the reading ended: "eof",
 *       "fatal:<message>", or "stop" after the data of an entry ended other
 *       than by "eof".
 *
 *       An entry is "<status>;<header>;<data>". <status> is "ok", or
 *       "warn:<message>" for ARCHIVE_WARN. <header> is, separated by ",":
 *       archive_format, the path, the mode in octal, uid, gid, nlink, the
 *       size, the birth, modification, access and change times in seconds,
 *       the device number (signed, as wide as dev_t), the symbolic link and
 *       the hard link; "~" for what is not set. <data> is the length of the
 *       data, its FNV-1a hash, the messages of the ARCHIVE_WARN calls in
 *       order ("-" if none, else joined by "."), and its end: "eof",
 *       "fatal:<message>", "stuck" when archive_read_data_block keeps
 *       returning nothing without reading anything (a zisofs block with
 *       bytes after its end, which libarchive never gets past), or "limit"
 *       when there is more than 64 MiB (the length and hash are then of
 *       the first 64 MiB).
 *
 *   write <options> <entries>
 *       An image written by archive_write_set_format_iso9660 with
 *       <options> (archive_write_set_options, a string; "-" for
 *       none) from <entries>, lines separated by "\n", each
 *         <type> <mode> <uid> <gid> <mtime> <atime> <ctime> <birthtime>
 *         <path> <link> <size> <rdev>
 *       <type> "f" (a file of <size> bytes, byte i being i*7 plus the
 *       path's length, mod 256), "d", "l" (a symbolic link to <link>),
 *       "h" (a hard link to <link>), "c", "b", "p" (character, block
 *       device, FIFO); the mode in octal, times in seconds ("~" for no
 *       birth time), the path and link as byte strings. Answered
 *       "ok <image>" or "err <message>".
 */

#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "archive.h"
#include "archive_entry.h"

#define LIMIT ((int64_t)64 << 20)

static char *line_buf;
static size_t line_cap;

static void out_char(char c) { putchar(c); }

static void out_str(const char *s) { fputs(s, stdout); }

static void out_hex(const unsigned char *p, size_t n)
{
	static const char digits[] = "0123456789abcdef";
	size_t i;

	if (n == 0) {
		out_char('-');
		return;
	}
	for (i = 0; i < n; i++) {
		out_char(digits[p[i] >> 4]);
		out_char(digits[p[i] & 15]);
	}
}

/* A C string as a byte string, or "~" for NULL. */
static void out_cstr(const char *s)
{
	if (s == NULL)
		out_char('~');
	else
		out_hex((const unsigned char *)s, strlen(s));
}

static void out_error(struct archive *a)
{
	out_cstr(archive_error_string(a));
}

static int unhex_digit(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

/* A byte string in place; returns its length, or -1. */
static long unhex(char *s)
{
	size_t n, i;

	if (strcmp(s, "-") == 0)
		return 0;
	n = strlen(s);
	if (n % 2 != 0)
		return -1;
	for (i = 0; i < n / 2; i++) {
		int hi = unhex_digit((unsigned char)s[2 * i]);
		int lo = unhex_digit((unsigned char)s[2 * i + 1]);
		if (hi < 0 || lo < 0)
			return -1;
		s[i] = (char)(hi * 16 + lo);
	}
	return (long)(n / 2);
}

/* The read callback of mode "s": the whole image in one block, no seek. */
struct stream {
	const unsigned char *data;
	size_t size;
	int done;
};

static la_ssize_t stream_read(struct archive *a, void *client, const void **buff)
{
	struct stream *s = client;

	(void)a;
	if (s->done) {
		*buff = NULL;
		return 0;
	}
	s->done = 1;
	*buff = s->data;
	return (la_ssize_t)s->size;
}

static void out_time(int set, time_t t)
{
	if (set)
		printf("%lld", (long long)t);
	else
		out_char('~');
}

static void out_header(struct archive *a, struct archive_entry *e)
{
	printf("%d,", archive_format(a));
	out_cstr(archive_entry_pathname(e));
	printf(",%o,%lld,%lld,%u,", (unsigned)archive_entry_mode(e),
	    (long long)archive_entry_uid(e), (long long)archive_entry_gid(e),
	    (unsigned)archive_entry_nlink(e));
	if (archive_entry_size_is_set(e))
		printf("%lld", (long long)archive_entry_size(e));
	else
		out_char('~');
	out_char(',');
	out_time(archive_entry_birthtime_is_set(e), archive_entry_birthtime(e));
	out_char(',');
	out_time(archive_entry_mtime_is_set(e), archive_entry_mtime(e));
	out_char(',');
	out_time(archive_entry_atime_is_set(e), archive_entry_atime(e));
	out_char(',');
	out_time(archive_entry_ctime_is_set(e), archive_entry_ctime(e));
	printf(",%lld,", (long long)archive_entry_rdev(e));
	out_cstr(archive_entry_symlink(e));
	out_char(',');
	out_cstr(archive_entry_hardlink(e));
}

/* A growing string, for the warnings of an entry's data. */
struct text {
	char *s;
	size_t len, cap;
};

static void text_add(struct text *t, const char *s)
{
	size_t n = strlen(s);

	if (t->len + n + 1 > t->cap) {
		size_t cap = t->cap ? t->cap * 2 : 256;
		while (cap < t->len + n + 1)
			cap *= 2;
		t->s = realloc(t->s, cap);
		if (t->s == NULL)
			abort();
		t->cap = cap;
	}
	memcpy(t->s + t->len, s, n + 1);
	t->len += n;
}

static void text_add_hex(struct text *t, const char *s)
{
	static const char digits[] = "0123456789abcdef";
	char pair[3] = { 0, 0, 0 };

	if (s == NULL) {
		text_add(t, "~");
		return;
	}
	if (*s == '\0') {
		text_add(t, "-");
		return;
	}
	for (; *s != '\0'; s++) {
		pair[0] = digits[(unsigned char)*s >> 4];
		pair[1] = digits[(unsigned char)*s & 15];
		text_add(t, pair);
	}
}

/* The data of the current entry; returns 0 when reading can go on. */
static int out_data(struct archive *a)
{
	uint64_t hash = 0xcbf29ce484222325ULL;
	int64_t total = 0, last_position = -1;
	struct text warnings = { NULL, 0, 0 };
	int empty = 0, go_on = 0;
	const char *end = NULL;

	for (;;) {
		const void *buff;
		size_t size, i;
		la_int64_t offset;
		int r = archive_read_data_block(a, &buff, &size, &offset);

		if (r == ARCHIVE_WARN) {
			if (warnings.len > 0)
				text_add(&warnings, ".");
			text_add_hex(&warnings, archive_error_string(a));
			empty = 0;
			continue;
		}
		if (r == ARCHIVE_OK && size == 0) {
			/* A call that returned nothing: twice in a row
			 * without the position moving, and it is stuck. */
			int64_t position = archive_filter_bytes(a, 0);
			if (empty && position == last_position) {
				end = "stuck";
				break;
			}
			empty = 1;
			last_position = position;
			continue;
		}
		empty = 0;
		if (r == ARCHIVE_OK) {
			int over = 0;
			if (offset != total) {
				end = "bad";
				break;
			}
			/* Up to the limit: past it, the data is not compared. */
			if ((int64_t)size > LIMIT - total) {
				size = (size_t)(LIMIT - total);
				over = 1;
			}
			for (i = 0; i < size; i++) {
				hash ^= ((const unsigned char *)buff)[i];
				hash *= 0x100000001b3ULL;
			}
			total += (int64_t)size;
			if (over) {
				end = "limit";
				break;
			}
			continue;
		}
		if (r == ARCHIVE_EOF) {
			end = "eof";
			go_on = 1;
		} else if (r == ARCHIVE_FATAL) {
			end = "fatal:";
		} else {
			end = "bad";
		}
		break;
	}
	printf(";%lld,%016llx,%s,%s", (long long)total, (unsigned long long)hash,
	    warnings.len > 0 ? warnings.s : "-", end);
	if (strcmp(end, "fatal:") == 0)
		out_error(a);
	free(warnings.s);
	return go_on ? 0 : 1;
}

static void do_read(char *mode, char *image)
{
	struct archive *a;
	struct archive_entry *e;
	struct stream s;
	long n = unhex(image);
	int r;

	if (strlen(mode) != 3 || n < 0) {
		out_str("bad");
		return;
	}
	a = archive_read_new();
	archive_read_support_format_iso9660(a);
	if (mode[1] == '0')
		archive_read_set_format_option(a, "iso9660", "joliet", NULL);
	if (mode[2] == '0')
		archive_read_set_format_option(a, "iso9660", "rockridge", NULL);
	if (mode[0] == 'm') {
		r = archive_read_open_memory(a, image, (size_t)n);
	} else {
		s.data = (const unsigned char *)image;
		s.size = (size_t)n;
		s.done = 0;
		r = archive_read_open(a, &s, NULL, stream_read, NULL);
	}
	if (r != ARCHIVE_OK) {
		out_str("fatal:");
		out_error(a);
		archive_read_free(a);
		return;
	}
	out_str("open");
	for (;;) {
		r = archive_read_next_header(a, &e);
		out_char('|');
		if (r == ARCHIVE_EOF) {
			out_str("eof");
			break;
		}
		if (r == ARCHIVE_FATAL) {
			out_str("fatal:");
			out_error(a);
			break;
		}
		if (r == ARCHIVE_OK) {
			out_str("ok");
		} else if (r == ARCHIVE_WARN) {
			out_str("warn:");
			out_error(a);
		} else {
			printf(" bad");
			break;
		}
		out_char(';');
		out_header(a, e);
		if (out_data(a) != 0) {
			out_str("|stop");
			break;
		}
	}
	archive_read_free(a);
}

/* The image being written, grown as the writer calls back. */
struct sink {
	unsigned char *data;
	size_t size, cap;
};

static la_ssize_t sink_write(struct archive *a, void *client, const void *buff, size_t n)
{
	struct sink *s = client;

	(void)a;
	if (s->size + n > s->cap) {
		size_t cap = s->cap ? s->cap : 1 << 16;
		unsigned char *p;
		while (cap < s->size + n)
			cap *= 2;
		p = realloc(s->data, cap);
		if (p == NULL)
			return -1;
		s->data = p;
		s->cap = cap;
	}
	memcpy(s->data + s->size, buff, n);
	s->size += n;
	return (la_ssize_t)n;
}

static void do_write(char *options, char *entries)
{
	struct archive *a;
	struct sink s = { NULL, 0, 0 };
	long n = unhex(entries);
	char *line, *next;
	char *data = NULL;
	size_t data_cap = 0;
	int failed = 0;

	if (n < 0 || (strcmp(options, "-") != 0 && unhex(options) < 0)) {
		out_str("bad");
		return;
	}
	entries[n] = '\0';
	a = archive_write_new();
	archive_write_set_format_iso9660(a);
	archive_write_set_bytes_per_block(a, 2048);
	archive_write_set_bytes_in_last_block(a, 1);
	if (strcmp(options, "-") != 0 &&
	    archive_write_set_options(a, options) != ARCHIVE_OK) {
		out_str("err ");
		out_error(a);
		archive_write_free(a);
		return;
	}
	if (archive_write_open2(a, &s, NULL, sink_write, NULL, NULL) != ARCHIVE_OK) {
		out_str("err ");
		out_error(a);
		archive_write_free(a);
		return;
	}
	for (line = entries; *line != '\0' && !failed; line = next) {
		char *field[12], *save = NULL;
		const char *type, *birth;
		char *path, *link;
		unsigned mode;
		long long uid, gid, mtime, atime, ctime_, size, rdev;
		long path_len, link_len;
		int nfields = 0;
		struct archive_entry *e;

		next = strchr(line, '\n');
		if (next != NULL)
			*next++ = '\0';
		else
			next = line + strlen(line);
		for (char *f = strtok_r(line, " ", &save); f != NULL && nfields < 12;
		    f = strtok_r(NULL, " ", &save))
			field[nfields++] = f;
		if (nfields != 12) {
			out_str("bad");
			archive_write_free(a);
			free(s.data);
			return;
		}
		type = field[0];
		mode = (unsigned)strtoul(field[1], NULL, 8);
		uid = atoll(field[2]);
		gid = atoll(field[3]);
		mtime = atoll(field[4]);
		atime = atoll(field[5]);
		ctime_ = atoll(field[6]);
		birth = field[7];
		path = field[8];
		link = field[9];
		size = atoll(field[10]);
		rdev = atoll(field[11]);
		path_len = unhex(path);
		link_len = unhex(link);
		if (path_len < 0 || link_len < 0) {
			out_str("bad");
			archive_write_free(a);
			free(s.data);
			return;
		}
		path[path_len] = '\0';
		link[link_len] = '\0';
		e = archive_entry_new();
		archive_entry_set_pathname(e, path);
		archive_entry_set_uid(e, uid);
		archive_entry_set_gid(e, gid);
		archive_entry_set_mtime(e, (time_t)mtime, 0);
		archive_entry_set_atime(e, (time_t)atime, 0);
		archive_entry_set_ctime(e, (time_t)ctime_, 0);
		if (strcmp(birth, "~") != 0)
			archive_entry_set_birthtime(e, (time_t)atoll(birth), 0);
		switch (type[0]) {
		case 'f':
			archive_entry_set_mode(e, AE_IFREG | (mode & 07777));
			archive_entry_set_size(e, size);
			break;
		case 'd':
			archive_entry_set_mode(e, AE_IFDIR | (mode & 07777));
			break;
		case 'l':
			archive_entry_set_mode(e, AE_IFLNK | (mode & 07777));
			archive_entry_set_symlink(e, link);
			break;
		case 'h':
			archive_entry_set_mode(e, AE_IFREG | (mode & 07777));
			archive_entry_set_hardlink(e, link);
			archive_entry_set_size(e, 0);
			break;
		case 'c':
			archive_entry_set_mode(e, AE_IFCHR | (mode & 07777));
			archive_entry_set_rdev(e, (dev_t)rdev);
			break;
		case 'b':
			archive_entry_set_mode(e, AE_IFBLK | (mode & 07777));
			archive_entry_set_rdev(e, (dev_t)rdev);
			break;
		default:
			archive_entry_set_mode(e, AE_IFIFO | (mode & 07777));
			break;
		}
		if (archive_write_header(a, e) < ARCHIVE_WARN) {
			failed = 1;
		} else if (type[0] == 'f' && size > 0) {
			long long i;
			if ((size_t)size > data_cap) {
				free(data);
				data = malloc((size_t)size);
				data_cap = data != NULL ? (size_t)size : 0;
			}
			if (data == NULL) {
				failed = 1;
			} else {
				for (i = 0; i < size; i++)
					data[i] = (char)(i * 7 + path_len);
				if (archive_write_data(a, data, (size_t)size) < 0)
					failed = 1;
			}
		}
		archive_entry_free(e);
	}
	free(data);
	if (!failed && archive_write_close(a) != ARCHIVE_OK)
		failed = 1;
	if (failed) {
		out_str("err ");
		out_error(a);
	} else {
		out_str("ok ");
		out_hex(s.data, s.size);
	}
	archive_write_free(a);
	free(s.data);
}

/*
 * timegm as glibc's does it, for libarchive on macOS (see config.h): the
 * fields may be out of range, and dates before 1900 are fine.
 */
time_t oracle_timegm(struct tm *tm);

time_t oracle_timegm(struct tm *tm)
{
	long long year = 1900LL + tm->tm_year, month = tm->tm_mon, y, era, yoe, mp, doe, days;

	year += month >= 0 ? month / 12 : -((11 - month) / 12);
	month = ((month % 12) + 12) % 12 + 1;
	y = month <= 2 ? year - 1 : year;
	era = (y >= 0 ? y : y - 399) / 400;
	yoe = y - era * 400;
	mp = (month + 9) % 12;
	doe = yoe * 365 + yoe / 4 - yoe / 100 + (153 * mp + 2) / 5;
	days = era * 146097 + doe - 719468 + tm->tm_mday - 1;
	return (time_t)(days * 86400 + tm->tm_hour * 3600LL + tm->tm_min * 60LL + tm->tm_sec);
}

int main(void)
{
	/* Joliet names come out in the locale's charset: UTF-8. */
	if (setlocale(LC_ALL, "C.UTF-8") == NULL &&
	    setlocale(LC_ALL, "en_US.UTF-8") == NULL &&
	    setlocale(LC_ALL, "UTF-8") == NULL) {
		fprintf(stderr, "iso-oracle: no UTF-8 locale\n");
		return 1;
	}
	for (;;) {
		ssize_t len = getline(&line_buf, &line_cap, stdin);
		char *cmd, *arg1, *arg2, *save;

		if (len < 0)
			break;
		if (len > 0 && line_buf[len - 1] == '\n')
			line_buf[len - 1] = '\0';
		cmd = strtok_r(line_buf, " ", &save);
		arg1 = strtok_r(NULL, " ", &save);
		arg2 = strtok_r(NULL, " ", &save);
		if (cmd == NULL) {
			out_str("bad");
		} else if (strcmp(cmd, "sizes") == 0) {
			printf("ok %zu %zu", sizeof(mode_t), sizeof(dev_t));
		} else if (strcmp(cmd, "read") == 0 && arg1 != NULL && arg2 != NULL) {
			do_read(arg1, arg2);
		} else if (strcmp(cmd, "write") == 0 && arg1 != NULL && arg2 != NULL) {
			do_write(arg1, arg2);
		} else {
			out_str("bad");
		}
		out_char('\n');
		fflush(stdout);
	}
	free(line_buf);
	return 0;
}
