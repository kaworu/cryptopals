#ifndef SRC_ANALYSIS_H
#define SRC_ANALYSIS_H
/*
 * src/analysis.h
 *
 * Plain text analysis stuff for cryptopals.com challenges.
 */
#include "bytes.h"


/*
 * Returns the probability that the given buffer is plain text english.
 *
 * The returned values is in the [0, 1] range, 0.0 meaning the algorithm is sure
 * it is not plain text english and 1.0 meaning it is 100% sure it is plain text
 * english.
 *
 * Returns -1.0 if the provided bytes struct argument is NULL.
 */
double	analysis_looks_like_english(const struct bytes *buf);

/*
 * Single-byte XOR cipher brute-force.
 *
 * Brute force the given bytes struct assuming that it is "encrypted" with a
 * single-byte XOR cipher and that the plaintext is english. Returns the
 * "decrypted" version of the buffer. If `p' is not NULL it will be set to the
 * probability that the returned buffer is valid english plaintext on success.
 *
 * Returns NULL if bytes_copy() failed.
 */
struct bytes	*analysis_single_byte_xor(const struct bytes *buf, double *p);

#endif /* ndef SRC_ANALYSIS_H */

