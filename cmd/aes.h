#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>

/* Both return 0, or -1 on input. keylen is 16 or 32 bytes. */

int aes_cbc_decrypt(const uint8_t *key, size_t keylen, const uint8_t iv[16],
                    const uint8_t *in, size_t len, uint8_t *out);
int pkcs7_unpad(const uint8_t *in, size_t len, size_t *outlen);

#endif
