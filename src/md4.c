/*
 * md4.c
 *
 * MD4 stuff for cryptopals.com challenges.
 *
 * See RFC 1320.
 */
#include "compat.h"
#include "md4.h"


/* Constants for md4_transform() routine. */
#define	S11	 3
#define	S12	 7
#define	S13	11
#define	S14	19
#define	S21	 3
#define	S22	 5
#define	S23	 9
#define	S24	13
#define	S31	 3
#define	S32	 9
#define	S33	11
#define	S34	15

/* F, G and H are basic MD4 functions. */
#define	F(x, y, z)	(((x) & (y)) | ((~x) & (z)))
#define	G(x, y, z)	(((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define	H(x, y, z)	((x) ^ (y) ^ (z))

/* ROTATE_LEFT rotates x left n bits. */
#define	ROTATE_LEFT(x, n)	(((x) << (n)) | ((x) >> (32 - (n))))

/* FF, GG and HH are transformations for rounds 1, 2 and 3 */
/* Rotation is separate from addition to prevent recomputation */
#define	FF(a, b, c, d, x, s)	do {           \
		(a) += F((b), (c), (d)) + (x); \
		(a)  = ROTATE_LEFT((a), (s));  \
	} while (/* CONSTCOND */0)
#define	GG(a, b, c, d, x, s)	do {                                  \
		(a) += G((b), (c), (d)) + (x) + (uint32_t)0x5a827999; \
		(a)  = ROTATE_LEFT((a), (s));                         \
	} while (/* CONSTCOND */0)
#define	HH(a, b, c, d, x, s)	do {                                  \
		(a) += H((b), (c), (d)) + (x) + (uint32_t)0x6ed9eba1; \
		(a)  = ROTATE_LEFT((a), (s));                         \
	} while (/* CONSTCOND */0)


/*
 * Helper processing one 512-bits input message block into the given MD4
 * Intermediate Hash State.
 */
static void	md4_transform(uint32_t *state, const uint8_t *block);


size_t
md4_hashlength(void)
{
	/* MD4 hashes are 128-bit long */
	return (128 / 8);
}


struct bytes *
md4_hash(const struct bytes *msg)
{
	struct bytes *digest = NULL;
	int success = 0;

	/* default initial MD4 Intermediate Hash State */
	struct md4_ctx ctx = {
		.len = 0,
		.state = {
			0x67452301,
			0xEFCDAB89,
			0x98BADCFE,
			0x10325476,
		},
	};

	if (md4_hash_ctx(&ctx, msg) != 0)
		goto cleanup;

	digest = bytes_from_uint32_le(ctx.state, 4);
	if (digest == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	explicit_bzero(&ctx, sizeof(struct md4_ctx));
	if (!success) {
		bytes_free(digest);
		digest = NULL;
	}
	return (digest);
}


int
md4_hash_ctx(struct md4_ctx *ctx, const struct bytes *msg)
{
	struct bytes *block = NULL;
	int success = 0;

	/* sanity checks */
	if (ctx == NULL || msg == NULL)
		goto cleanup;

	/* process each "complete" message block */
	const size_t nblock = msg->len / 64;
	for (size_t i = 0; i < nblock; i++)
		md4_transform(ctx->state, msg->data + 64 * i);
	ctx->len += msg->len;

	/* the padded block */
	block = bytes_zeroed(64);
	if (block == NULL)
		goto cleanup;
	/* count of message bytes in the padded block */
	const size_t restlen = msg->len % 64;
	/* copy what is left of the message to process into the padded block */
	if (bytes_sput(block, 0, msg, 64 * nblock, restlen) != 0)
		goto cleanup;
	/* Add the first padding bytes, a `1' bit followed by zeroes */
	block->data[restlen] = 0x80;
	if (restlen >= 56) {
		/* We don't have enough space in the padding block to fit the
		   0x80 byte and the 64-bits length, So we process the padded
		   block as-is (i.e. without the length) */
		md4_transform(ctx->state, block->data);
		/* reset the padding block, the length will be set in the last 8
		   bytes and it will be processed as the second padding block */
		bytes_bzero(block);
	}

	/* set the 64-bits message length (count of bits) in the last 8 bytes of
	   the padded block; low-order word first, least significant byte
	   first */
	const uint64_t nbits = 8 * ctx->len;
	block->data[56] = nbits >>  0;
	block->data[57] = nbits >>  8;
	block->data[58] = nbits >> 16;
	block->data[59] = nbits >> 24;
	block->data[60] = nbits >> 32;
	block->data[61] = nbits >> 40;
	block->data[62] = nbits >> 48;
	block->data[63] = nbits >> 56;

	/* process the last padding block */
	md4_transform(ctx->state, block->data);

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(block);
	return (success ? 0 : -1);
}


static void
md4_transform(uint32_t *state, const uint8_t *block)
{
	uint32_t a = state[0];
	uint32_t b = state[1];
	uint32_t c = state[2];
	uint32_t d = state[3];
	uint32_t x[16] = { 0 };

	for (size_t i = 0; i < sizeof(x) / sizeof(*x); i++) {
		/* NOTE: little endian, least significant byte first */
		const uint32_t ll = block[4 * i + 0];
		const uint32_t lh = block[4 * i + 1];
		const uint32_t hl = block[4 * i + 2];
		const uint32_t hh = block[4 * i + 3];
		x[i] = (hh << 24) | (hl << 16) | (lh << 8) | ll;
	}

	/* Round 1 */
	FF(a, b, c, d, x[ 0], S11); /* 1 */
	FF(d, a, b, c, x[ 1], S12); /* 2 */
	FF(c, d, a, b, x[ 2], S13); /* 3 */
	FF(b, c, d, a, x[ 3], S14); /* 4 */
	FF(a, b, c, d, x[ 4], S11); /* 5 */
	FF(d, a, b, c, x[ 5], S12); /* 6 */
	FF(c, d, a, b, x[ 6], S13); /* 7 */
	FF(b, c, d, a, x[ 7], S14); /* 8 */
	FF(a, b, c, d, x[ 8], S11); /* 9 */
	FF(d, a, b, c, x[ 9], S12); /* 10 */
	FF(c, d, a, b, x[10], S13); /* 11 */
	FF(b, c, d, a, x[11], S14); /* 12 */
	FF(a, b, c, d, x[12], S11); /* 13 */
	FF(d, a, b, c, x[13], S12); /* 14 */
	FF(c, d, a, b, x[14], S13); /* 15 */
	FF(b, c, d, a, x[15], S14); /* 16 */

	/* Round 2 */
	GG(a, b, c, d, x[ 0], S21); /* 17 */
	GG(d, a, b, c, x[ 4], S22); /* 18 */
	GG(c, d, a, b, x[ 8], S23); /* 19 */
	GG(b, c, d, a, x[12], S24); /* 20 */
	GG(a, b, c, d, x[ 1], S21); /* 21 */
	GG(d, a, b, c, x[ 5], S22); /* 22 */
	GG(c, d, a, b, x[ 9], S23); /* 23 */
	GG(b, c, d, a, x[13], S24); /* 24 */
	GG(a, b, c, d, x[ 2], S21); /* 25 */
	GG(d, a, b, c, x[ 6], S22); /* 26 */
	GG(c, d, a, b, x[10], S23); /* 27 */
	GG(b, c, d, a, x[14], S24); /* 28 */
	GG(a, b, c, d, x[ 3], S21); /* 29 */
	GG(d, a, b, c, x[ 7], S22); /* 30 */
	GG(c, d, a, b, x[11], S23); /* 31 */
	GG(b, c, d, a, x[15], S24); /* 32 */

	/* Round 3 */
	HH(a, b, c, d, x[ 0], S31); /* 33 */
	HH(d, a, b, c, x[ 8], S32); /* 34 */
	HH(c, d, a, b, x[ 4], S33); /* 35 */
	HH(b, c, d, a, x[12], S34); /* 36 */
	HH(a, b, c, d, x[ 2], S31); /* 37 */
	HH(d, a, b, c, x[10], S32); /* 38 */
	HH(c, d, a, b, x[ 6], S33); /* 39 */
	HH(b, c, d, a, x[14], S34); /* 40 */
	HH(a, b, c, d, x[ 1], S31); /* 41 */
	HH(d, a, b, c, x[ 9], S32); /* 42 */
	HH(c, d, a, b, x[ 5], S33); /* 43 */
	HH(b, c, d, a, x[13], S34); /* 44 */
	HH(a, b, c, d, x[ 3], S31); /* 45 */
	HH(d, a, b, c, x[11], S32); /* 46 */
	HH(c, d, a, b, x[ 7], S33); /* 47 */
	HH(b, c, d, a, x[15], S34); /* 48 */

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	/* Zeroize sensitive information. */
	explicit_bzero(x, sizeof(x));
}
