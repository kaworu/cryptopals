/*
 * sha256.c
 *
 * SHA-256 stuff for cryptopals.com challenges.
 *
 * See RFC 6234.
 */
#include "compat.h"
#include "sha256.h"


/* Rotate right and rotate left  operations (§ 3) */
#define	ROTR(x, n)	(((x) >> (n)) | ((x) << (32 - (n))))
#define	ROTL(x, n)	(((x) << (n)) | ((x) >> (32 - (n))))

/* SHA-256 local functions (§ 5.1) */
#define	CH(x, y, z)	(((x) & (y)) ^ (~(x) & (z)))
#define	MAJ(x, y, z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define	BSIG0(x)	(ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define	BSIG1(x)	(ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define	SSIG0(x)	(ROTR(x,  7) ^ ROTR(x, 18) ^ ((x) >>  3))
#define	SSIG1(x)	(ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))


/*
 * Helper processing one 512-bits input message block into the given SHA-256
 * Intermediate Hash State.
 */
static void	sha256_process_message_block(const uint8_t *block, uint32_t *H);


/* SHA-256 K constants (§ 5.1) */
static const uint32_t k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};


size_t
sha256_hashlength(void)
{
	/* SHA-256 hashes are 256-bit long */
	return (256 / 8);
}


size_t
sha256_blocksize(void)
{
	return (512 / 8);
}


struct bytes *
sha256_hash(const struct bytes *msg)
{
	struct bytes *digest = NULL;
	int success = 0;

	/* default initial SHA-256 Intermediate Hash State */
	struct sha256_ctx ctx = {
		.len = 0,
		.state = {
			0x6a09e667,
			0xbb67ae85,
			0x3c6ef372,
			0xa54ff53a,
			0x510e527f,
			0x9b05688c,
			0x1f83d9ab,
			0x5be0cd19,
		},
	};

	if (sha256_hash_ctx(&ctx, msg) != 0)
		goto cleanup;

	digest = bytes_from_uint32_be(ctx.state, 8);
	if (digest == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	explicit_bzero(&ctx, sizeof(struct sha256_ctx));
	if (!success) {
		bytes_free(digest);
		digest = NULL;
	}
	return (digest);
}


int
sha256_hash_ctx(struct sha256_ctx *ctx, const struct bytes *msg)
{
	/* max total message length, in byte */
	const uint64_t maxlen = UINT64_MAX / 8;
	const size_t blocksize = sha256_blocksize();
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
	const size_t nblock = msg->len / blocksize;
	for (size_t i = 0; i < nblock; i++)
		sha256_process_message_block(msg->data + blocksize * i, H);
	ctx->len += msg->len;

	/* the padded block */
	block = bytes_zeroed(blocksize);
	if (block == NULL)
		goto cleanup;
	/* count of message bytes in the padded block */
	const size_t restlen = msg->len % blocksize;
	/* copy what is left of the message to process into the padded block */
	if (bytes_sput(block, 0, msg, blocksize * nblock, restlen) != 0)
		goto cleanup;
	/* Add the first padding bytes, a `1' bit followed by zeroes */
	block->data[restlen] = 0x80;
	if (restlen >= 56) {
		/* We don't have enough space in the padding block to fit the
		   0x80 byte and the 64-bits length, So we process the padded
		   block as-is (i.e. without the length) */
		sha256_process_message_block(block->data, H);
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
	sha256_process_message_block(block->data, H);

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(block);
	return (success ? 0 : -1);
}


static void
sha256_process_message_block(const uint8_t *block, uint32_t *H)
{
	uint32_t W[64];
	uint32_t a, b, c, d, e, f, g, h;

	/* 1. Prepare the message schedule W */
	for (size_t t = 0, i = 0; t < 16; t++, i += 4) {
		const uint32_t hh = block[i + 0];
		const uint32_t hl = block[i + 1];
		const uint32_t lh = block[i + 2];
		const uint32_t ll = block[i + 3];
		W[t] = (hh << 24) | (hl << 16) | (lh << 8) | ll;
	}
	for (size_t t = 16; t < 64; t++) {
		W[t] = SSIG1(W[t - 2]) + W[t - 7] + SSIG0(W[t - 15]) + W[t - 16];
	}

	/* 2. Initialize the working variables */
	a = H[0];
	b = H[1];
	c = H[2];
	d = H[3];
	e = H[4];
	f = H[5];
	g = H[6];
	h = H[7];

	/* 3. Perform the main hash computation */
	for (size_t t = 0; t < 64; t++) {
		uint32_t tmp1 = h + BSIG1(e) + CH(e, f, g) + k[t] + W[t];
		uint32_t tmp2 = BSIG0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + tmp1;
		d = c;
		c = b;
		b = a;
		a = tmp1 + tmp2;
	}

	/* 4. Compute the intermediate hash value H(i) */
	H[0] += a;
	H[1] += b;
	H[2] += c;
	H[3] += d;
	H[4] += e;
	H[5] += f;
	H[6] += g;
	H[7] += h;

	explicit_bzero(W, sizeof(W));
}
