#ifndef SHA256_H
#define SHA256_H
/*
 * sha256.h
 *
 * SHA-256 stuff for cryptopals.com challenges.
 *
 * See RFC 6234.
 */
#include "bytes.h"


/* SHA-256 context */
struct sha256_ctx {
	/* message length */
	uint64_t len;
	/* SHA-256 Intermediate Hash State */
	uint32_t state[8];
};


/*
 * Returns the size of a SHA-256 hash result, in bytes (32).
 */
size_t	sha256_hashlength(void);

/*
 * Returns the size of a SHA-256 compression block, in bytes (64).
 */
size_t	sha256_blocksize(void);

/*
 * Compute the SHA-256 Hash of the given message.
 *
 * Returns the resulting hash, or NULL on error.
 */
struct bytes	*sha256_hash(const struct bytes *msg);

/*
 * Compute the SHA-256 Hash of the given message starting from the given SHA-256
 * context. Useful to perform SHA-256 length extension.
 *
 * this function will compute and process the padding of msg.
 *
 * Returns 0 on success, -1 on error.
 */
int	sha256_hash_ctx(struct sha256_ctx *ctx, const struct bytes *msg);

#endif /* ndef SHA256_H */
