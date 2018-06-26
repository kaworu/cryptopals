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


/* SHA-1 context */
struct sha1_ctx {
	/* message length */
	uint64_t len;
	/* SHA-1 Intermediate Hash State */
	uint32_t state[5];
};


/*
 * Compute the SHA-1 Hash of the given message.
 *
 * Returns the resulting hash, or NULL on error.
 */
struct bytes	*sha1_hash(const struct bytes *msg);

/*
 * Compute the SHA-1 Hash of the given message starting from the given SHA-1
 * context. Useful to perform SHA-1 length extension.
 *
 * Unlike the SHA1Input() function from the RFC, this function will compute and
 * process the padding of msg.
 *
 * Returns 0 on success, -1 on error.
 */
int	sha1_hash_ctx(struct sha1_ctx *ctx, const struct bytes *msg);

#endif /* ndef SHA1_H */
