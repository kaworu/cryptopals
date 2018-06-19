#ifndef BREAK_CTR_H
#define BREAK_CTR_H
/*
 * break_ctr.h
 *
 * CTR analysis stuff for cryptopals.com challenges.
 */
#include "bytes.h"


/*
 * CTR "Decryption" Oracle as described by Set 3 / Challenge 19.
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

/*
 * CTR Encryption Oracle as described by Set 4 / Challenge 26.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(), or NULL if malloc(3) failed or if any given parameter is NULL.
 */
struct bytes	*ctr_bitflipping_oracle(const struct bytes *payload,
		    const struct bytes *key, uint64_t nonce);

/*
 * CTR Decryption Oracle as described by Set 4 / Challenge 26.
 *
 * Returns -1 on error, 1 if the given ciphertext has the admin=true tuple,
 * 0 otherwise.
 */
int		ctr_bitflipping_verifier(const struct bytes *ciphertext,
		    const struct bytes *key, uint64_t nonce);

/*
 * CTR Attack as described by Set 4 / Challenge 26.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(), or NULL if malloc(3) failed or if any given parameter is NULL.
 */
struct bytes	*ctr_bitflipping_breaker(const void *key, uint64_t nonce);

#endif /* ndef BREAK_CTR_H */
