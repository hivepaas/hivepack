/*
 * The part of GnuTLS's crypto API that libzip's GnuTLS backend uses, for the
 * oracle: HMAC-SHA1, on nettle's, as GnuTLS computes it.
 */
#ifndef HIVEPACK_ORACLE_GNUTLS_CRYPTO_H
#define HIVEPACK_ORACLE_GNUTLS_CRYPTO_H

#include <stdlib.h>

#include <nettle/hmac.h>
#include <nettle/sha1.h>

#define GNUTLS_MAC_SHA1 3

typedef struct hmac_sha1_ctx *gnutls_hmac_hd_t;

static inline int gnutls_hmac_init(gnutls_hmac_hd_t *dig, int algorithm, const void *key, size_t keylen) {
    if (algorithm != GNUTLS_MAC_SHA1 || (*dig = malloc(sizeof(**dig))) == NULL)
        return -1;
    hmac_sha1_set_key(*dig, keylen, (const uint8_t *)key);
    return 0;
}

static inline int gnutls_hmac(gnutls_hmac_hd_t handle, const void *text, size_t textlen) {
    hmac_sha1_update(handle, textlen, (const uint8_t *)text);
    return 0;
}

static inline void gnutls_hmac_output(gnutls_hmac_hd_t handle, void *digest) {
    hmac_sha1_digest(handle, SHA1_DIGEST_SIZE, (uint8_t *)digest);
}

static inline void gnutls_hmac_deinit(gnutls_hmac_hd_t handle, void *digest) {
    if (digest != NULL)
        hmac_sha1_digest(handle, SHA1_DIGEST_SIZE, (uint8_t *)digest);
    free(handle);
}

#endif
