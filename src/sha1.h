#ifndef SHA1_H
#define SHA1_H
/*
 * sha1.h
 *
 * SHA-1 stuff for cryptopals.com challenges.
 *
 * See RFC 3174.
 */
#include "bytes.h"


/*
 * Compute the SHA-1 Hash of the given message.
 *
 * Returns the resulting hash, or NULL on error.
 */
struct bytes	*sha1_hash(const struct bytes *msg);

#endif /* ndef SHA1_H */
