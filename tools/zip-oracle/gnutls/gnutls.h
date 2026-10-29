/*
 * The part of GnuTLS that libzip's GnuTLS backend (zip_crypto_gnutls.h)
 * uses, for the oracle: random bytes, which oracle.c gives from a stream it
 * restarts before each zip_close, so that encrypting is repeatable. AES and
 * PBKDF2 come from nettle, as in GnuTLS itself.
 */
#ifndef HIVEPACK_ORACLE_GNUTLS_H
#define HIVEPACK_ORACLE_GNUTLS_H

#include <stddef.h>

#define GNUTLS_RND_KEY 2

/* In oracle.c. */
int gnutls_rnd(int level, void *data, size_t len);

#endif
