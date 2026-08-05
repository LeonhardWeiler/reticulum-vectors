#ifndef AES256_H
#define AES256_H

#include <stddef.h>
#include <stdint.h>

/* Both return 0, or -1 on input the caller must then reject. */

int aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                       const uint8_t *in, size_t len, uint8_t *out);
int pkcs7_unpad(const uint8_t *in, size_t len, size_t *outlen);

#endif
