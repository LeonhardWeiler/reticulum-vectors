#ifndef AES256_H
#define AES256_H

#include <stddef.h>
#include <stdint.h>

/* Decrypts len bytes, which must be a non-zero multiple of 16, in
 * place-safe fashion into out. Returns 0, or -1 on a bad length. */
int aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                       const uint8_t *in, size_t len, uint8_t *out);

/* Strips PKCS7 padding, writing the unpadded length to outlen.
 * Returns 0, or -1 if the padding is not well formed. */
int pkcs7_unpad(const uint8_t *in, size_t len, size_t *outlen);

#endif
