#ifndef ECB_H
#define ECB_H
/*
 * ecb.h
 *
 * Electronic Codebook mode of operation.
 */
#include "bytes.h"
#include "block_cipher.h"


/* per block cipher implementation routines */

/* nope */
struct bytes	*nope_ecb_encrypt(const struct bytes *plaintext,
		    const struct bytes *key);
struct bytes	*nope_ecb_decrypt(const struct bytes *ciphertext,
		    const struct bytes *key);

/* AES-128 */
struct bytes	*aes_128_ecb_encrypt(const struct bytes *plaintext,
		    const struct bytes *key);
struct bytes	*aes_128_ecb_decrypt(const struct bytes *ciphertext,
		    const struct bytes *key);

#endif /* ndef ECB_H */
