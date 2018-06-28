/*
 * sha1.c
 *
 * SHA-1 stuff for cryptopals.com challenges.
 *
 * See RFC 3174.
 */
#include "compat.h"
#include "sha1.h"


/*
 * Helper processing one 512-bits input message block into the given SHA-1
 * Intermediate Hash State.
 */
static void	sha1_process_message_block(const uint8_t *block, uint32_t *H);


size_t
sha1_hash_len(void)
{
	/* SHA-1 hashes are 160-bit long */
	return (160 / 8);
}


struct bytes *
sha1_hash(const struct bytes *msg)
{
	struct bytes *digest = NULL;
	int success = 0;

	/* default initial SHA-1 Intermediate Hash State */
	struct sha1_ctx ctx = {
		.len = 0,
		.state = {
			0x67452301,
			0xEFCDAB89,
			0x98BADCFE,
			0x10325476,
			0xC3D2E1F0,
		},
	};

	if (sha1_hash_ctx(&ctx, msg) != 0)
		goto cleanup;

	digest = bytes_from_uint32_be(ctx.state, 5);
	if (digest == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	explicit_bzero(&ctx, sizeof(struct sha1_ctx));
	if (!success) {
		bytes_free(digest);
		digest = NULL;
	}
	return (digest);
}


int
sha1_hash_ctx(struct sha1_ctx *ctx, const struct bytes *msg)
{
	/* max total message length, in byte */
	const uint64_t maxlen = UINT64_MAX / 8;
	struct bytes *block = NULL;
	int success = 0;

	/* sanity checks */
	if (ctx == NULL)
		goto cleanup;
	if (ctx->len > maxlen)
		goto cleanup;
	if (msg == NULL || msg->len > (maxlen - ctx->len))
		goto cleanup;

	uint32_t *H = ctx->state;

	/* process each "complete" message block */
	const size_t nblock = msg->len / 64;
	for (size_t i = 0; i < nblock; i++)
		sha1_process_message_block(msg->data + 64 * i, H);
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
		sha1_process_message_block(block->data, H);
		/* reset the padding block, the length will be set in the last 8
		   bytes and it will be processed as the second padding block */
		bytes_bzero(block);
	}

	/* set the 64-bits message length (count of bits) in the last 8 bytes of
	   the padded block, most significant byte first */
	const uint64_t nbits = 8 * ctx->len;
	block->data[56] = nbits >> 56;
	block->data[57] = nbits >> 48;
	block->data[58] = nbits >> 40;
	block->data[59] = nbits >> 32;
	block->data[60] = nbits >> 24;
	block->data[61] = nbits >> 16;
	block->data[62] = nbits >>  8;
	block->data[63] = nbits >>  0;

	/* process the last padding block */
	sha1_process_message_block(block->data, H);

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(block);
	return (success ? 0 : -1);
}


static void
sha1_process_message_block(const uint8_t *block, uint32_t *H)
#define	S(n, word)	(((word) << (n)) | ((word) >> (32 - (n))))
{
	uint32_t W[80];

	/*
	 * a. Divide M(i) into 16 words W(0), W(1), ... , W(15), where W(0) is
	 * the left-most word.
	 */
	for (size_t t = 0; t < 16; t++) {
		const uint32_t hh = block[4 * t + 0];
		const uint32_t hl = block[4 * t + 1];
		const uint32_t lh = block[4 * t + 2];
		const uint32_t ll = block[4 * t + 3];
		W[t] = (hh << 24) | (hl << 16) | (lh << 8) | ll;
	}

	/*
	 * b. For t = 16 to 79 let
	 *        W(t) = S^1(W(t-3) XOR W(t-8) XOR W(t-14) XOR W(t-16)).
	 */
	for (size_t t = 16; t < 80; t++)
		W[t] = S(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);

	/*
	 * c. Let A = H0, B = H1, C = H2, D = H3, E = H4.
	 */
	uint32_t A = H[0];
	uint32_t B = H[1];
	uint32_t C = H[2];
	uint32_t D = H[3];
	uint32_t E = H[4];

	/*
	 * d. For t = 0 to 79 do
	 *        TEMP = S^5(A) + f(t;B,C,D) + E + W(t) + K(t);
	 *        E = D;  D = C;  C = S^30(B);  B = A; A = TEMP;
	 */
	for (size_t t = 0; t < 80; t++) {
		uint32_t f, k;
		if (t < 20) {
			f = ((B & C) | ((~B) & D));
			k = 0x5A827999;
		} else if (t < 40) {
			f = (B ^ C ^ D);
			k = 0x6ED9EBA1;
		} else if (t < 60) {
			f = ((B & C) | (B & D) | (C & D));
			k = 0x8F1BBCDC;
		} else {
			f = (B ^ C ^ D);
			k = 0xCA62C1D6;
		}
		uint32_t temp = S(5, A) + f + E + W[t] + k;
		E = D;
		D = C;
		C = S(30, B);
		B = A;
		A = temp;
	}

	/*
	 * e. Let H0 = H0 + A, H1 = H1 + B, H2 = H2 + C, H3 = H3 + D, H4 = H4
	 *    + E.
	 */
	H[0] += A;
	H[1] += B;
	H[2] += C;
	H[3] += D;
	H[4] += E;

	explicit_bzero(W, sizeof(W));
}
#undef	S
