/*
 * The configuration of the libarchive 3.8.10 sources that tools/iso-oracle
 * is built with, in place of the config.h libarchive's CMake or configure
 * script writes: the reader and writer of ISO 9660 images, with zlib for
 * zisofs, on Linux or macOS. Only what those sources ask for is here.
 */

#define HAVE_STDINT_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_STRINGS_H 1
#define HAVE_ERRNO_H 1
#define HAVE_UNISTD_H 1
#define HAVE_FCNTL_H 1
#define HAVE_FCNTL 1
#define HAVE_LIMITS_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_TIME_H 1
#define HAVE_WCHAR_H 1
#define HAVE_LOCALE_H 1
#define HAVE_LANGINFO_H 1
#define HAVE_NL_LANGINFO 1
#define HAVE_ZLIB_H 1
#define HAVE_TIMEGM 1
#define HAVE_GMTIME_R 1
#define HAVE_LOCALTIME_R 1
#define HAVE_MKSTEMP 1
#define HAVE_WCSCPY 1
#define HAVE_WCSLEN 1
#define HAVE_WMEMCMP 1
#define HAVE_WMEMCPY 1
#define HAVE_WMEMMOVE 1
#define HAVE_WCRTOMB 1
#define HAVE_MBRTOWC 1
#define HAVE_EILSEQ 1
#define HAVE_DECL_SIZE_MAX 1
#define HAVE_DECL_SSIZE_MAX 1
#define HAVE_DECL_INT32_MAX 1
#define HAVE_DECL_INT32_MIN 1
#define HAVE_DECL_UINT32_MAX 1
#define HAVE_DECL_INT64_MAX 1
#define HAVE_DECL_INT64_MIN 1
#define HAVE_DECL_UINT64_MAX 1
#define HAVE_DECL_INTMAX_MAX 1
#define HAVE_DECL_INTMAX_MIN 1
#define HAVE_DECL_UINTMAX_MAX 1
#define HAVE_UINTMAX_T 1
#define HAVE_INTMAX_T 1
#define HAVE_UINT64_T 1
#define HAVE_INT64_T 1
#define HAVE_UINT32_T 1
#define HAVE_INT32_T 1
#define HAVE_UINT16_T 1
#define HAVE_INT16_T 1
#define HAVE_UINT8_T 1
#define HAVE_WORKING_EXT2_IOC_GETFLAGS 0
#define SIZEOF_INT 4
#define SIZEOF_LONG 8
#define SIZEOF_WCHAR_T 4
#define ARCHIVE_ACL_FREEBSD 0
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

/*
 * macOS's timegm gives up on dates before 1900 (once the time zone is
 * taken off), where glibc's goes on; libarchive then gives 1970. hivepack-iso
 * computes them as glibc does, so on macOS libarchive calls oracle.c's
 * oracle_timegm, the same arithmetic, instead.
 */
#if defined(__APPLE__)
#define timegm oracle_timegm
#endif
