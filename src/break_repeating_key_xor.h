#ifndef BREAK_REPEATING_KEY_XOR_H
#define BREAK_REPEATING_KEY_XOR_H
/*
 * break_repeating_key_xor.h
 *
 * Breaking Repeating-key XOR "cipher" (aka Vigenère cipher).
 */
#include "bytes.h"


/*
 * Repeating-key XOR "cipher" (aka "Vigenere") brute-force.
 *
 * Brute force the given bytes struct assuming that it is "encrypted" with a
 * repeating-key XOR cipher and that the plaintext is english. Returns the
 * "decrypted" version of the buffer.
 *
 * If `key' is not NULL it will be set to the key guessed on success.
 *
 * If `score' is not NULL it will be set to the score of the result on success
 * (see looks_like_english()).
 *
 * Returns NULL if bytes_dup() failed, a valid bytes struct pointer otherwise
 * that should be passed to bytes_free().
 *
 * XXX: limited to english plaintext.
 */
struct bytes	*break_repeating_key_xor(const struct bytes *ciphertext,
		    struct bytes **key_p, double *score_p);

#endif /* ndef BREAK_REPEATING_KEY_XOR_H */
