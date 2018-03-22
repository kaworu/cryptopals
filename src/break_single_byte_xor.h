#ifndef BREAK_SINGLE_BYTE_XOR_H
#define BREAK_SINGLE_BYTE_XOR_H
/*
 * break_single_byte_xor.h
 *
 * Breaking Single-byte XOR "cipher".
 */
#include "bytes.h"
#include "break_plaintext.h"


/*
 * Single-byte XOR "cipher" brute-force.
 *
 * Brute force the given bytes struct assuming that it is "encrypted" with a
 * single-byte XOR cipher and using the provided `method' as heuristic. Returns
 * the "decrypted" version of the buffer that should be passed to bytes_free().
 *
 * If `key_p' is not NULL it will be set to the key guessed on success and
 * should be passed to bytes_free().
 *
 * If `score_p' is not NULL it will be set to the score of the result on success
 * (returned by the given `method').
 *
 * Returns NULL if the given `ciphertext' is NULL or is empty, or bytes_dup()
 * failed, or the provided `method' is NULL or failed.
 */
struct bytes	*break_single_byte_xor(
		    const struct bytes *ciphertext,
		    break_plaintext_func_t method,
		    struct bytes **key_p, double *score_p);

#endif /* ndef BREAK_SINGLE_BYTE_XOR_H */
