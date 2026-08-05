#ifndef HMAC_H
#define HMAC_H

#include <stddef.h>
#include <stdint.h>

/* The largest message either function is asked to authenticate. A
 * Reticulum token is bounded by the MTU of 500 bytes; the margin is
 * for the corpus, which also authenticates whole vectors. */
#define HMAC_MAXMSG 8192

void hmac_sha256(const uint8_t *key, size_t keylen,
                 const uint8_t *data, size_t datalen, uint8_t out[32]);

void hkdf_sha256(const uint8_t *ikm, size_t ikmlen,
                 const uint8_t *salt, size_t saltlen,
                 const uint8_t *context, size_t contextlen,
                 uint8_t *out, size_t outlen);

#endif
