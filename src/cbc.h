#ifndef CBC_H
#define CBC_H
/*
 * cbc.h
 *
 * Cipher Block Chaining mode of operation.
 */
#include "bytes.h"

/* per block cipher implementation routines */

/* nope */
struct bytes	*nope_cbc_encrypt(const struct bytes *plaintext,
		    const struct bytes *key, const struct bytes *iv);
struct bytes	*nope_cbc_decrypt(const struct bytes *ciphertext,
		    const struct bytes *key, const struct bytes *iv);

/* AES-128 */
struct bytes	*aes_128_cbc_encrypt(const struct bytes *plaintext,
		    const struct bytes *key, const struct bytes *iv);
struct bytes	*aes_128_cbc_decrypt(const struct bytes *ciphertext,
		    const struct bytes *key, const struct bytes *iv);

#endif /* ndef CBC_H */
