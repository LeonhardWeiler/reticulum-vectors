/* HMAC-SHA256 (RFC 2104) and HKDF-SHA256 (RFC 5869). */

#include "hmac.h"
#include "sha256.h"

#include <stdlib.h>
#include <string.h>

#define BLOCK 64
#define HASH  32

void hmac_sha256(const uint8_t *key, size_t keylen,
                 const uint8_t *data, size_t datalen, uint8_t out[HASH])
{
	uint8_t k[BLOCK], inner[BLOCK + HMAC_MAXMSG], outer[BLOCK + HASH];
	uint8_t digest[HASH];
	size_t i;

	if (datalen > HMAC_MAXMSG)
		abort();

	memset(k, 0, BLOCK);
	if (keylen > BLOCK)
		sha256(key, keylen, k);
	else
		memcpy(k, key, keylen);

	for (i = 0; i < BLOCK; i++)
		inner[i] = k[i] ^ 0x36;
	memcpy(inner + BLOCK, data, datalen);
	sha256(inner, BLOCK + datalen, digest);

	for (i = 0; i < BLOCK; i++)
		outer[i] = k[i] ^ 0x5c;
	memcpy(outer + BLOCK, digest, HASH);
	sha256(outer, BLOCK + HASH, out);
}

/* RNS/Cryptography/HKDF.py#hkdf. An absent salt is 32 zero bytes and an
 * absent context is empty. */
void hkdf_sha256(const uint8_t *ikm, size_t ikmlen,
                 const uint8_t *salt, size_t saltlen,
                 const uint8_t *context, size_t contextlen,
                 uint8_t *out, size_t outlen)
{
	uint8_t zeros[HASH], prk[HASH], block[HASH];
	uint8_t input[HASH + HMAC_MAXMSG];
	size_t produced = 0, blocklen = 0;
	unsigned counter = 0;

	if (outlen == 0 || ikmlen == 0)
		abort();

	if (salt == NULL || saltlen == 0) {
		memset(zeros, 0, HASH);
		salt = zeros;
		saltlen = HASH;
	}

	hmac_sha256(salt, saltlen, ikm, ikmlen, prk);

	while (produced < outlen) {
		size_t n = 0, take;

		memcpy(input + n, block, blocklen);        n += blocklen;
		if (contextlen > 0) {
			memcpy(input + n, context, contextlen); n += contextlen;
		}
		input[n++] = (uint8_t)((counter + 1) % 256);

		hmac_sha256(prk, HASH, input, n, block);
		blocklen = HASH;
		counter++;

		take = outlen - produced < HASH ? outlen - produced : HASH;
		memcpy(out + produced, block, take);
		produced += take;
	}
}
