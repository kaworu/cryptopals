#ifndef XOR_H
#define XOR_H
/*
 * xor.h
 *
 * XOR "cipher" stuff for cryptopals.com challenges.
 */
#include "bytes.h"

/*
 * Perform a binary XOR of two bytes struct of the same length. After this
 * function returns, the first bytes struct argument holds the result.
 *
 * Returns 0 on success, -1 if any of the argument is NULL or if their length
 * doesn't match.
 */
int	bytes_xor(struct bytes *buf, const struct bytes *mask);

/*
 * Implement a repeating-key XOR cipher.
 *
 * Returns 0 on success, -1 if any of the argument is NULL or the key length is
 * zero.
 */
int	repeating_key_xor(struct bytes *buf, const struct bytes *key);

#endif /* ndef XOR_H */
