#ifndef BREAK_CBC_H
#define BREAK_CBC_H
/*
 * break_cbc.h
 *
 * CBC analysis stuff for cryptopals.com challenges.
 */
#include "bytes.h"

/*
 * CBC Encryption function as described by Set 2 / Challenge 16.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(), or NULL if malloc(3) failed or if any given parameter is NULL.
 */
struct bytes	*cbc_bitflipping_encrypt(const struct bytes *payload,
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
 * Return the payload with `=' and `;' escaped as `%3D' respectively `%3B', or
 * NULL if malloc(3) failed or the provided payload is NULL.
 */
struct bytes	*cbc_bitflipping_escape(const struct bytes *payload);

/*
 * CBC Attack as described by Set 2 / Challenge 16.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(), or NULL if malloc(3) failed or if any given parameter is NULL.
 */
struct bytes	*cbc_bitflipping_breaker(const void *key, const void *iv);

/*
 * CBC Decryption Oracle as described by Set 3 / Challenge 17.
 *
 * Returns 0 if the padding is valid, 1 if the padding is invalid, -1 on error.
 */
int	cbc_padding_oracle(const struct bytes *ciphertext,
	    const struct bytes *key, const struct bytes *iv);

/*
 * CBC Attack as described by Set 3 / Challenge 17.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(), or NULL if malloc(3) failed or if any given parameter is NULL.
 */
struct bytes	*cbc_padding_breaker(const struct bytes *ciphertext,
		    const void *key, const struct bytes *iv);

/*
 * Decrypt the given ciphertext with the provided key/iv using AES128-CBC and
 * Detect if the plaintext contains high ASCII.
 *
 * Returns -1 on error, 1 if at least one high ASCII byte is found, and 0
 * otherwise.
 *
 * If error_p is not NULL, it is not modified when -1 is returned, set to the
 * decrypted plaintext when 1 is returned and must be passed to bytes_free(3) by
 * the caller, and set to NULL when 0 is returned.
 */
int	cbc_high_ascii_oracle(const struct bytes *ciphertext,
		    const void *key, const struct bytes *iv,
		    struct bytes **error_p);

/*
 * Recover function from Set 4 / Challenge 27.
 *
 * Returns the recovered key or NULL on error.
 */
struct bytes	*cbc_key_as_iv_breaker(const struct bytes *ciphertext,
		    const void *key_iv);

#endif /* ndef BREAK_CBC_H */
