#ifndef SRC_ANALYSIS_H
#define SRC_ANALYSIS_H
/*
 * src/analysis.h
 *
 * Plain text analysis stuff for cryptopals.com challenges.
 */
#include "bytes.h"


/*
 * Returns the score of the given buffer as plaintext english, -1.0 if the
 * provided bytes struct argument is NULL.
 */
double	analysis_looks_like_english(const struct bytes *buf);

/*
 * Single-byte XOR cipher brute-force.
 *
 * Brute force the given bytes struct assuming that it is "encrypted" with a
 * single-byte XOR cipher and that the plaintext is english. Returns the
 * "decrypted" version of the buffer. If `s' is not NULL it will be set to the
 * score of the result on success (see analysis_looks_like_english()).
 *
 * Returns NULL if bytes_copy() failed.
 */
struct bytes	*analysis_single_byte_xor(const struct bytes *buf, double *s);

#endif /* ndef SRC_ANALYSIS_H */

