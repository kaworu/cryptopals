#ifndef BREAK_CTR_H
#define BREAK_CTR_H
/*
 * break_ctr.h
 *
 * CTR analysis stuff for cryptopals.com challenges.
 */
#include "bytes.h"


/*
 * CBC "Decryption" Oracle as described by Set 3 / Challenge 19.
 *
 * Return the guessed keystream.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(), or NULL if malloc(3) failed or if any given parameter is NULL.
 */
struct bytes	*break_ctr_fixed_nonce(struct bytes **ciphertexts, size_t count);

/*
 * "edit" function from Set 4 / Challenge 25.
 */
struct bytes	*aes_128_ctr_edit_oracle(const struct bytes *ciphertext,
		    const struct bytes *key, uint64_t nonce,
		    size_t offset, const struct bytes *replacement);

/*
 * "recover" function from Set 4 / Challenge 25.
 */
struct bytes	*aes_128_ctr_edit_breaker(const struct bytes *ciphertext,
		    const struct bytes *key, const uint64_t nonce);

#endif /* ndef BREAK_CTR_H */
