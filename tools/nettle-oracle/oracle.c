/*
 * The nettle side of hivepack-crypto's comparison tests.
 *
 * It reads one request per line on stdin and answers each on one line of
 * stdout, by calling nettle 3.10.2: the library libzip's GnuTLS backend
 * takes AES and PBKDF2 from, and an implementation apart from BearSSL, which
 * hivepack-crypto ports. The Rust tests ask the port the same questions and
 * compare the answers as text. scripts/testdata.py builds it from the nettle
 * release sources.
 *
 * Byte strings are hexadecimal, and "-" is an empty one.
 *
 *   aes <key> <blocks>
 *       Each 16-byte block of <blocks> encrypted with nettle_aes128_encrypt,
 *       nettle_aes192_encrypt or nettle_aes256_encrypt, as the key has 16,
 *       24 or 32 bytes. Answered "ok <encrypted>", or "err" for a key of
 *       another length.
 *
 *   sha1 <data>
 *       Answered "ok <digest>".
 *
 *   hmac <key> <data>
 *       HMAC-SHA1. Answered "ok <mac>".
 *
 *   pbkdf2 <iterations> <length> <password> <salt>
 *       pbkdf2_hmac_sha1, at least one iteration (nettle asserts it).
 *       Answered "ok <key>".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nettle/aes.h>
#include <nettle/hmac.h>
#include <nettle/pbkdf2.h>
#include <nettle/sha1.h>

static int digit(char c) {
    return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10;
}

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

static void answer(const unsigned char *bytes, size_t len) {
    fputs("ok ", stdout);
    put_hex(bytes, len);
    putchar('\n');
}

static void do_aes(const char *key_hex, const char *blocks_hex) {
    size_t key_len, len, i;
    unsigned char *key = unhex(key_hex, &key_len);
    unsigned char *data = unhex(blocks_hex, &len);
    unsigned char *out = malloc(len + 1);
    len -= len % AES_BLOCK_SIZE;
    if (key_len == AES128_KEY_SIZE) {
        struct aes128_ctx ctx;
        aes128_set_encrypt_key(&ctx, key);
        for (i = 0; i < len; i += AES_BLOCK_SIZE)
            aes128_encrypt(&ctx, AES_BLOCK_SIZE, out + i, data + i);
    } else if (key_len == AES192_KEY_SIZE) {
        struct aes192_ctx ctx;
        aes192_set_encrypt_key(&ctx, key);
        for (i = 0; i < len; i += AES_BLOCK_SIZE)
            aes192_encrypt(&ctx, AES_BLOCK_SIZE, out + i, data + i);
    } else if (key_len == AES256_KEY_SIZE) {
        struct aes256_ctx ctx;
        aes256_set_encrypt_key(&ctx, key);
        for (i = 0; i < len; i += AES_BLOCK_SIZE)
            aes256_encrypt(&ctx, AES_BLOCK_SIZE, out + i, data + i);
    } else {
        puts("err");
        len = (size_t)-1;
    }
    if (len != (size_t)-1)
        answer(out, len);
    free(key);
    free(data);
    free(out);
}

static void do_sha1(const char *data_hex) {
    size_t len;
    unsigned char *data = unhex(data_hex, &len);
    unsigned char digest[SHA1_DIGEST_SIZE];
    struct sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, len, data);
    sha1_digest(&ctx, SHA1_DIGEST_SIZE, digest);
    answer(digest, SHA1_DIGEST_SIZE);
    free(data);
}

static void do_hmac(const char *key_hex, const char *data_hex) {
    size_t key_len, len;
    unsigned char *key = unhex(key_hex, &key_len);
    unsigned char *data = unhex(data_hex, &len);
    unsigned char mac[SHA1_DIGEST_SIZE];
    struct hmac_sha1_ctx ctx;
    hmac_sha1_set_key(&ctx, key_len, key);
    hmac_sha1_update(&ctx, len, data);
    hmac_sha1_digest(&ctx, SHA1_DIGEST_SIZE, mac);
    answer(mac, SHA1_DIGEST_SIZE);
    free(key);
    free(data);
}

static void do_pbkdf2(unsigned iterations, size_t length, const char *password_hex,
                      const char *salt_hex) {
    size_t password_len, salt_len;
    unsigned char *password = unhex(password_hex, &password_len);
    unsigned char *salt = unhex(salt_hex, &salt_len);
    unsigned char *out = malloc(length + 1);
    if (iterations == 0) {
        puts("bad");
    } else {
        pbkdf2_hmac_sha1(password_len, password, iterations, salt_len, salt, length, out);
        answer(out, length);
    }
    free(password);
    free(salt);
    free(out);
}

int main(void) {
    size_t cap = 1 << 20;
    char *line = malloc(cap);
    while (fgets(line, (int)cap, stdin)) {
        size_t n = strlen(line);
        char *words[5];
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
        for (word = strtok(line, " "); word && count < 5; word = strtok(NULL, " "))
            words[count++] = word;
        if (count == 3 && strcmp(words[0], "aes") == 0)
            do_aes(words[1], words[2]);
        else if (count == 2 && strcmp(words[0], "sha1") == 0)
            do_sha1(words[1]);
        else if (count == 3 && strcmp(words[0], "hmac") == 0)
            do_hmac(words[1], words[2]);
        else if (count == 5 && strcmp(words[0], "pbkdf2") == 0)
            do_pbkdf2((unsigned)strtoul(words[1], NULL, 10), (size_t)strtoul(words[2], NULL, 10),
                      words[3], words[4]);
        else
            puts("bad");
        fflush(stdout);
    }
    free(line);
    return 0;
}
