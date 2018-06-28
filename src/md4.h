#ifndef MD4_H
#define MD4_H
/*
 * md4.h
 *
 * MD4 stuff for cryptopals.com challenges.
 *
 * See RFC 1320.
 */
#include "bytes.h"


/* MD4 context */
struct md4_ctx {
	/* message length */
	uint64_t len;
	/* MD4 State */
	uint32_t state[4];
};


/*
 * Returns the size of a MD4 hash result, in byte (16).
 */
size_t	md4_hashlength(void);

/*
 * Compute the MD4 Hash of the given message.
 *
 * Returns the resulting hash, or NULL on error.
 */
struct bytes	*md4_hash(const struct bytes *msg);

/*
 * Compute the MD4 Hash of the given message starting from the given MD4
 * context. Useful to perform MD4 length extension.
 *
 * Unlike the MD4Update() function from the RFC, this function will compute and
 * process the padding of msg.
 *
 * Returns 0 on success, -1 on error.
 */
int	md4_hash_ctx(struct md4_ctx *ctx, const struct bytes *msg);

#endif /* ndef MD4_H */
