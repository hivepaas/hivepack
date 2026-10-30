/*
 * config.h for building libzip 1.12.1 into the oracle on 64-bit Linux and
 * macOS, in place of the one libzip's CMake build writes from
 * config.h.in: what those systems have, with libbzip2 (bzip2 1.0.8's
 * sources) but not the other optional libraries. The crypto backend is
 * GnuTLS's, on nettle's sources and the part of GnuTLS in gnutls/. oracle.c gives zip_random_uint32 (temporary file
 * names) apart from the random bytes, so that encrypting draws the same
 * bytes from gnutls_rnd whatever file is written.
 */
#ifndef HAD_CONFIG_H
#define HAD_CONFIG_H
#ifndef _HAD_ZIPCONF_H
#include "zipconf.h"
#endif
#define ENABLE_FDOPEN
#define HAVE_FILENO
#define HAVE_FCHMOD
#define HAVE_FSEEKO
#define HAVE_FTELLO
#define HAVE_LOCALTIME_R
#define HAVE_MKSTEMP
#define HAVE_SNPRINTF
#define HAVE_STRCASECMP
#define HAVE_STRDUP
#define HAVE_STRTOLL
#define HAVE_STRTOULL
#define HAVE_STDBOOL_H
#define HAVE_STRINGS_H
#define HAVE_UNISTD_H
#define HAVE_DIRENT_H
#define HAVE_CRYPTO
#define HAVE_GNUTLS
#define HAVE_RANDOM_UINT32
#define HAVE_LIBBZ2
#define SIZEOF_OFF_T 8
#define SIZEOF_SIZE_T 8
#define PACKAGE "libzip"
#define VERSION "1.12.1"
#endif /* HAD_CONFIG_H */
