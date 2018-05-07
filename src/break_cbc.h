#ifndef BREAK_CBC_H
#define BREAK_CBC_H
/*
 * break_cbc.h
 *
 * CBC analysis stuff for cryptopals.com challenges.
 */
#include "bytes.h"

/*
 * CBC Encryption Oracle as described by Set 2 / Challenge 16.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(), or NULL if malloc(3) failed or if any given parameter is NULL.
 */
struct bytes	*cbc_bitflipping_oracle(const struct bytes *payload,
		    const struct bytes *key, const struct bytes *iv);

/*
 * CBC Decryption Oracle as described by Set 2 / Challenge 16.
 *
 * Returns -1 on error, 1 if the given ciphertext has the admin=true tuple,
 * 0 otherwise.
 */
int		cbc_bitflipping_verifier(const struct bytes *ciphertext,
		    const struct bytes *key, const struct bytes *iv);

/*
 * CBC Attack as described by Set 2 / Challenge 16.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(), or NULL if malloc(3) failed or if any given parameter is NULL.
 */
struct bytes	*cbc_bitflipping_breaker(const void *key, const void *iv);

#endif /* ndef BREAK_CBC_H */
