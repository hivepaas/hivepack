/*
 * The libarchive side of hivepack-cpio's comparison tests.
 *
 * It reads one request per line on stdin and answers each on one line of
 * stdout, by calling libarchive 3.8.10, whose cpio reader and RPM filter
 * hivepack-cpio ports, and whose cpio writers make the archives the tests
 * read. The Rust tests ask the port the same questions and compare the
 * answers as text. scripts/testdata.py builds it from the libarchive
 * release sources, with config.h.
 *
 * Byte strings are hexadecimal, "-" is an empty one and "~" none at all.
 * A request the oracle cannot answer, or an answer libarchive should not
 * give, has "BAD" in it.
 *
 *   sizes
 *       The sizes of mode_t and dev_t, which libarchive stores an entry's
 *       mode and device numbers in, and what the system's makedev, major
 *       and minor make of some numbers: "ok <mode_t> <dev_t>
 *       <makedev(0x12345678, 0x9abcdef0)> <major(0x9abcdef0)>
 *       <minor(0x9abcdef0)>", the last three as signed numbers.
 *
 *   read <mode> <archive>
 *       Every entry of <archive>, read with archive_read_support_format_cpio
 *       and archive_read_support_filter_rpm, and all of its data with
 *       archive_read_data_block. <mode> is three characters: "m" to open
 *       the archive in memory (archive_read_open_memory) or "s" to give it
 *       as one block through a read callback that cannot seek; "d" to read
 *       each entry's data, or "k" to leave it to archive_read_next_header
 *       to skip; "1" for the "pwb" option, "0" without. Answered with
 *       fields separated by "|": "open,<n>" with n the number of RPM
 *       filters, or "fatal:<message>" alone when the archive is not
 *       opened; then one field per entry, and how the reading ended: "eof",
 *       "fatal:<message>", or "stop" after the data of an entry ended
 *       other than by "eof".
 *
 *       An entry is "<status>;<header>;<data>". <status> is "ok", or
 *       "warn:<message>" for ARCHIVE_WARN. <header> is, separated by ",":
 *       archive_format, the path, the mode in octal, uid, gid, nlink, the
 *       inode, the size, the modification time, dev, devmajor, devminor,
 *       rdev, rdevmajor and rdevminor (signed, as wide as dev_t), the
 *       symbolic link and the hard link; "~" for what is not set. <data>
 *       is "skip" with "k", else the length of the data, its FNV-1a hash
 *       and its end: "eof" or "fatal:<message>".
 *
 *   rpm <archive>
 *       What libarchive's RPM filter gives of <archive>: read with
 *       archive_read_support_filter_rpm and the raw and empty formats, in
 *       memory. Answered "fatal:<message>" when it is not opened, else
 *       "ok <n>;<length>,<hash>,<end>": n the number of RPM filters, and
 *       the data of the raw entry (none for an empty input) as for "read".
 *
 *   write <format> <block> <entries>
 *       An archive written by archive_write_set_format_cpio_<format>
 *       ("odc", "newc", "bin" or "pwb") with archive_write_set_bytes_per_block
 *       <block> (and the last block not padded when it is 0; then one byte
 *       per block), from <entries>, lines separated by "\n", each
 *         <type> <mode> <uid> <gid> <nlink> <ino> <dev> <rdev> <mtime>
 *         <path> <link> <size>
 *       <type> "f" (a file of <size> bytes, byte i being i*7 plus the
 *       path's length, mod 256), "d", "l" (a symbolic link to <link>),
 *       "c", "b", "p", "s" (character, block device, FIFO, socket); the
 *       mode in octal; a device "<n>" (archive_entry_set_dev, _set_rdev)
 *       or "<major>:<minor>" (_set_devmajor and _set_devminor, and the same
 *       for rdev); the path and link as byte strings. An entry the writer
 *       refuses with ARCHIVE_FAILED is left out. Answered "ok <archive>" or
 *       "err <message>".
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#if defined(__linux__)
#include <sys/sysmacros.h>
#endif

#include "archive.h"
#include "archive_entry.h"

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

/* The read callback of mode "s": the whole archive in one block, no seek. */
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

static void out_header(struct archive *a, struct archive_entry *e)
{
	printf("%d,", archive_format(a));
	out_cstr(archive_entry_pathname(e));
	printf(",%o,%lld,%lld,%u,", (unsigned)archive_entry_mode(e),
	    (long long)archive_entry_uid(e), (long long)archive_entry_gid(e),
	    (unsigned)archive_entry_nlink(e));
	if (archive_entry_ino_is_set(e))
		printf("%lld", (long long)archive_entry_ino64(e));
	else
		out_char('~');
	out_char(',');
	if (archive_entry_size_is_set(e))
		printf("%lld", (long long)archive_entry_size(e));
	else
		out_char('~');
	out_char(',');
	if (archive_entry_mtime_is_set(e))
		printf("%lld", (long long)archive_entry_mtime(e));
	else
		out_char('~');
	printf(",%lld,%lld,%lld,%lld,%lld,%lld,",
	    (long long)archive_entry_dev(e), (long long)archive_entry_devmajor(e),
	    (long long)archive_entry_devminor(e), (long long)archive_entry_rdev(e),
	    (long long)archive_entry_rdevmajor(e),
	    (long long)archive_entry_rdevminor(e));
	out_cstr(archive_entry_symlink(e));
	out_char(',');
	out_cstr(archive_entry_hardlink(e));
}

/* The data of the current entry; returns 0 when reading can go on. */
static int out_data(struct archive *a)
{
	uint64_t hash = 0xcbf29ce484222325ULL;
	int64_t total = 0;
	const char *end = NULL;

	for (;;) {
		const void *buff;
		size_t size, i;
		la_int64_t offset;
		int r = archive_read_data_block(a, &buff, &size, &offset);

		if (r == ARCHIVE_OK) {
			if (offset != total) {
				end = "BAD";
				break;
			}
			for (i = 0; i < size; i++) {
				hash ^= ((const unsigned char *)buff)[i];
				hash *= 0x100000001b3ULL;
			}
			total += (int64_t)size;
			continue;
		}
		if (r == ARCHIVE_EOF)
			end = "eof";
		else if (r == ARCHIVE_FATAL)
			end = "fatal:";
		else
			end = "BAD";
		break;
	}
	printf(";%lld,%016llx,%s", (long long)total, (unsigned long long)hash, end);
	if (strcmp(end, "fatal:") == 0)
		out_error(a);
	return strcmp(end, "eof") == 0 ? 0 : 1;
}

/* Opens <archive> in memory or as a stream; returns what archive_read_open
 * does. */
static int open_archive(struct archive *a, char mode, struct stream *s,
    const char *archive, size_t n)
{
	if (mode == 'm')
		return archive_read_open_memory(a, archive, n);
	s->data = (const unsigned char *)archive;
	s->size = n;
	s->done = 0;
	return archive_read_open(a, s, NULL, stream_read, NULL);
}

static void do_read(char *mode, char *archive)
{
	struct archive *a;
	struct archive_entry *e;
	struct stream s;
	long n = unhex(archive);
	int r;

	if (strlen(mode) != 3 || n < 0) {
		out_str("BAD");
		return;
	}
	a = archive_read_new();
	archive_read_support_format_cpio(a);
	archive_read_support_filter_rpm(a);
	if (mode[2] == '1')
		archive_read_set_format_option(a, "cpio", "pwb", "1");
	r = open_archive(a, mode[0], &s, archive, (size_t)n);
	if (r != ARCHIVE_OK) {
		out_str("fatal:");
		out_error(a);
		archive_read_free(a);
		return;
	}
	printf("open,%d", archive_filter_count(a) - 1);
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
			printf(" BAD");
			break;
		}
		out_char(';');
		out_header(a, e);
		if (mode[1] == 'k') {
			out_str(";skip");
			continue;
		}
		if (out_data(a) != 0) {
			out_str("|stop");
			break;
		}
	}
	archive_read_free(a);
}

static void do_rpm(char *archive)
{
	struct archive *a;
	struct archive_entry *e;
	struct stream s;
	long n = unhex(archive);
	int r;

	if (n < 0) {
		out_str("BAD");
		return;
	}
	a = archive_read_new();
	archive_read_support_filter_rpm(a);
	archive_read_support_format_raw(a);
	archive_read_support_format_empty(a);
	r = open_archive(a, 'm', &s, archive, (size_t)n);
	if (r != ARCHIVE_OK) {
		out_str("fatal:");
		out_error(a);
		archive_read_free(a);
		return;
	}
	printf("ok %d", archive_filter_count(a) - 1);
	r = archive_read_next_header(a, &e);
	if (r == ARCHIVE_EOF)
		printf(";0,%016llx,eof", 0xcbf29ce484222325ULL);
	else if (r == ARCHIVE_OK)
		out_data(a);
	else
		out_str("BAD");
	archive_read_free(a);
}

/* The archive being written, grown as the writer calls back. */
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

/* A device "<n>" or "<major>:<minor>", set with dev or rdev's setters. */
static void set_device(struct archive_entry *e, const char *text, int rdev)
{
	const char *colon = strchr(text, ':');

	if (colon == NULL) {
		dev_t d = (dev_t)strtoull(text, NULL, 10);
		if (rdev)
			archive_entry_set_rdev(e, d);
		else
			archive_entry_set_dev(e, d);
		return;
	}
	if (rdev) {
		archive_entry_set_rdevmajor(e, (dev_t)strtoull(text, NULL, 10));
		archive_entry_set_rdevminor(e, (dev_t)strtoull(colon + 1, NULL, 10));
	} else {
		archive_entry_set_devmajor(e, (dev_t)strtoull(text, NULL, 10));
		archive_entry_set_devminor(e, (dev_t)strtoull(colon + 1, NULL, 10));
	}
}

static void do_write(char *format, char *block, char *entries)
{
	struct archive *a;
	struct sink s = { NULL, 0, 0 };
	long n = unhex(entries);
	char *line, *next;
	char *data = NULL;
	size_t data_cap = 0;
	int failed = 0, r, bytes_per_block = atoi(block);

	if (n < 0) {
		out_str("BAD");
		return;
	}
	entries[n] = '\0';
	a = archive_write_new();
	if (strcmp(format, "odc") == 0)
		r = archive_write_set_format_cpio_odc(a);
	else if (strcmp(format, "newc") == 0)
		r = archive_write_set_format_cpio_newc(a);
	else if (strcmp(format, "bin") == 0)
		r = archive_write_set_format_cpio_bin(a);
	else if (strcmp(format, "pwb") == 0)
		r = archive_write_set_format_cpio_pwb(a);
	else
		r = ARCHIVE_FATAL;
	if (r != ARCHIVE_OK) {
		out_str("BAD");
		archive_write_free(a);
		return;
	}
	if (bytes_per_block > 0) {
		archive_write_set_bytes_per_block(a, bytes_per_block);
	} else {
		archive_write_set_bytes_per_block(a, 512);
		archive_write_set_bytes_in_last_block(a, 1);
	}
	if (archive_write_open2(a, &s, NULL, sink_write, NULL, NULL) != ARCHIVE_OK) {
		out_str("err ");
		out_error(a);
		archive_write_free(a);
		return;
	}
	for (line = entries; *line != '\0' && !failed; line = next) {
		char *field[12], *save = NULL;
		char *path, *link;
		unsigned mode;
		long long size;
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
			out_str("BAD");
			archive_write_free(a);
			free(s.data);
			free(data);
			return;
		}
		mode = (unsigned)strtoul(field[1], NULL, 8);
		path = field[9];
		link = field[10];
		size = atoll(field[11]);
		path_len = unhex(path);
		link_len = unhex(link);
		if (path_len < 0 || link_len < 0) {
			out_str("BAD");
			archive_write_free(a);
			free(s.data);
			free(data);
			return;
		}
		path[path_len] = '\0';
		link[link_len] = '\0';
		e = archive_entry_new();
		archive_entry_set_pathname(e, path);
		archive_entry_set_uid(e, atoll(field[2]));
		archive_entry_set_gid(e, atoll(field[3]));
		archive_entry_set_nlink(e, (unsigned)strtoul(field[4], NULL, 10));
		archive_entry_set_ino64(e, atoll(field[5]));
		set_device(e, field[6], 0);
		set_device(e, field[7], 1);
		archive_entry_set_mtime(e, (time_t)atoll(field[8]), 0);
		archive_entry_set_size(e, 0);
		switch (field[0][0]) {
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
		case 'c':
			archive_entry_set_mode(e, AE_IFCHR | (mode & 07777));
			break;
		case 'b':
			archive_entry_set_mode(e, AE_IFBLK | (mode & 07777));
			break;
		case 's':
			archive_entry_set_mode(e, AE_IFSOCK | (mode & 07777));
			break;
		default:
			archive_entry_set_mode(e, AE_IFIFO | (mode & 07777));
			break;
		}
		r = archive_write_header(a, e);
		if (r == ARCHIVE_FAILED) {
			/* Left out. */
		} else if (r < ARCHIVE_WARN) {
			failed = 1;
		} else if (field[0][0] == 'f' && size > 0) {
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

int main(void)
{
	for (;;) {
		ssize_t len = getline(&line_buf, &line_cap, stdin);
		char *cmd, *arg1, *arg2, *arg3, *save;

		if (len < 0)
			break;
		if (len > 0 && line_buf[len - 1] == '\n')
			line_buf[len - 1] = '\0';
		cmd = strtok_r(line_buf, " ", &save);
		arg1 = strtok_r(NULL, " ", &save);
		arg2 = strtok_r(NULL, " ", &save);
		arg3 = strtok_r(NULL, " ", &save);
		if (cmd == NULL) {
			out_str("BAD");
		} else if (strcmp(cmd, "sizes") == 0) {
			printf("ok %zu %zu %lld %lld %lld", sizeof(mode_t), sizeof(dev_t),
			    (long long)makedev(0x12345678, 0x9abcdef0),
			    (long long)major((dev_t)0x9abcdef0),
			    (long long)minor((dev_t)0x9abcdef0));
		} else if (strcmp(cmd, "read") == 0 && arg1 != NULL && arg2 != NULL) {
			do_read(arg1, arg2);
		} else if (strcmp(cmd, "rpm") == 0 && arg1 != NULL) {
			do_rpm(arg1);
		} else if (strcmp(cmd, "write") == 0 && arg1 != NULL && arg2 != NULL &&
		    arg3 != NULL) {
			do_write(arg1, arg2, arg3);
		} else {
			out_str("BAD");
		}
		out_char('\n');
		fflush(stdout);
	}
	free(line_buf);
	return 0;
}
