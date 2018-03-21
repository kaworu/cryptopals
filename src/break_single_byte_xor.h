#ifndef BREAK_SINGLE_BYTE_XOR_H
#define BREAK_SINGLE_BYTE_XOR_H
/*
 * break_single_byte_xor.h
 *
 * Breaking Single-byte XOR "cipher".
 */
#include "bytes.h"


/*
 * Single-byte XOR "cipher" brute-force.
 *
 * Brute force the given bytes struct assuming that it is "encrypted" with a
 * single-byte XOR cipher and that the plaintext is english. Returns the
 * "decrypted" version of the buffer that should be passed to bytes_free().
 *
 * If `key' is not NULL it will be set to the key guessed on success.
 *
 * If `score' is not NULL it will be set to the score of the result on success
 * (see looks_like_english()).
 *
 * Returns NULL if the given `ciphertext' is NULL or bytes_dup() failed.
 */
struct bytes	*break_single_byte_xor(const struct bytes *ciphertext,
		    uint8_t *key, double *score);

#endif /* ndef BREAK_SINGLE_BYTE_XOR_H */
