#ifndef CTR_H
#define CTR_H
/*
 * ctr.h
 *
 * Counter mode of operation.
 */
#include "bytes.h"

/* per block cipher implementation routines */

/* nope */
struct bytes	*nope_ctr_encrypt(const struct bytes *plaintext,
		    const struct bytes *key, uint64_t nonce);
struct bytes	*nope_ctr_decrypt(const struct bytes *ciphertext,
		    const struct bytes *key, uint64_t nonce);

/* AES-128 */
struct bytes	*aes_128_ctr_encrypt(const struct bytes *plaintext,
		    const struct bytes *key, uint64_t nonce);
struct bytes	*aes_128_ctr_decrypt(const struct bytes *ciphertext,
		    const struct bytes *key, uint64_t nonce);

#endif /* ndef CTR_H */
