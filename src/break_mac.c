/*
 * break_mac.c
 *
 * MAC analysis stuff for cryptopals.com challenges.
 */
#include <string.h>

#include "compat.h"
#include "sha1.h"
#include "md4.h"
#include "mac.h"
#include "break_mac.h"


/* Describe how a 64-bit length value is encoded as bytes */
enum length_encoding {
	HIGH_WORD_FIRST_BE,
	LOW_WORD_FIRST_LE,
};


/*
 * Returns the padding bytes for a message of the given length, or NULL on
 * error.
 */
static struct bytes	*sha1_padding(size_t len);
static struct bytes	*md4_padding(size_t len);
static struct bytes	*padding(size_t len, enum length_encoding le);


int
extend_sha1_mac_keyed_prefix(const void *key,
		    const struct bytes *msg, const struct bytes *mac,
		    struct bytes **msg_p, struct bytes **mac_p)
#define oracle(m, c)	sha1_mac_keyed_prefix_verify(key, (m), (c))
{
	struct bytes *extension = NULL, *admin = NULL, *digest = NULL;
	struct sha1_ctx ctx;
	const size_t scount = sizeof(ctx.state) / sizeof(ctx.state[0]);
	uint32_t *h = NULL;
	size_t hcount = 0;
	int success = 0;

	if (msg == NULL || mac == NULL)
		goto cleanup;
	/* We'll try to break up to a keylength of 128 bytes. */
	if (msg->len >= ((UINT64_MAX - 128) / 8))
		goto cleanup;

	/* the extension payload */
	extension = bytes_from_str(";admin=true;");
	if (extension == NULL)
		goto cleanup;

	/* "unpack" the message's MAC so that we can use it to setup a SHA-1
	   Intermediate Hash State */
	h = bytes_to_uint32_be(mac, &hcount);
	if (h == NULL || hcount != scount)
		goto cleanup;

	/* try key length up to 1024-bit long, assume that it is a 8-bit
	   multiple */
	for (size_t keylen = 0; keylen <= 128; keylen++) {
		ctx.len = keylen + msg->len;
		/* generate the glue padding */
		struct bytes *glue = sha1_padding(ctx.len);
		if (glue == NULL)
			goto cleanup;
		/* update the length, now that we know the glue padding */
		ctx.len += glue->len;
		/* generate the full admin message */
		const struct bytes *const parts[] = { msg, glue, extension };
		admin = bytes_joined_const(parts, sizeof(parts) / sizeof(*parts));
		bytes_free(glue);
		if (admin == NULL)
			goto cleanup;
		/* reset the SHA-1 Intermediate Hash State */
		(void)memcpy(ctx.state, h, sizeof(ctx.state));
		/* extend the SHA-1 Intermediate Hash State */
		if (sha1_hash_ctx(&ctx, extension) != 0)
			goto cleanup;
		digest = bytes_from_uint32_be(ctx.state, scount);
		if (digest == NULL)
			goto cleanup;
		const int ret = oracle(admin, digest);
		if (ret == -1) /* error */
			goto cleanup;
		if (ret == 0) /* success */
			break;
		bytes_free(admin);
		admin = NULL;
		bytes_free(digest);
		digest = NULL;
	}
	if (admin == NULL || digest == NULL)
		goto cleanup;

	if (msg_p != NULL) {
		*msg_p = admin;
		admin = NULL;
	}
	if (mac_p != NULL) {
		*mac_p = digest;
		digest = NULL;
	}

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(admin);
	bytes_free(digest);
	freezero(h, hcount * sizeof(uint32_t));
	bytes_free(extension);
	return (success ? 0 : -1);
}
#undef oracle


int
extend_md4_mac_keyed_prefix(const void *key,
		    const struct bytes *msg, const struct bytes *mac,
		    struct bytes **msg_p, struct bytes **mac_p)
#define oracle(m, c)	md4_mac_keyed_prefix_verify(key, (m), (c))
{
	struct bytes *extension = NULL, *admin = NULL, *digest = NULL;
	struct md4_ctx ctx;
	const size_t scount = sizeof(ctx.state) / sizeof(ctx.state[0]);
	uint32_t *h = NULL;
	size_t hcount = 0;
	int success = 0;

	if (msg == NULL || mac == NULL)
		goto cleanup;
	/* We'll try to break up to a keylength of 128 bytes. */
	if (msg->len >= ((UINT64_MAX - 128) / 8))
		goto cleanup;

	/* the extension payload */
	extension = bytes_from_str(";admin=true;");
	if (extension == NULL)
		goto cleanup;

	/* "unpack" the message's MAC so that we can use it to setup a MD4
	   Intermediate Hash State */
	h = bytes_to_uint32_le(mac, &hcount);
	if (h == NULL || hcount != scount)
		goto cleanup;

	/* try key length up to 1024-bit long, assume that it is a 8-bit
	   multiple */
	for (size_t keylen = 0; keylen <= 128; keylen++) {
		ctx.len = keylen + msg->len;
		/* generate the glue padding */
		struct bytes *glue = md4_padding(ctx.len);
		if (glue == NULL)
			goto cleanup;
		/* update the length, now that we know the glue padding */
		ctx.len += glue->len;
		/* generate the full admin message */
		const struct bytes *const parts[] = { msg, glue, extension };
		admin = bytes_joined_const(parts, sizeof(parts) / sizeof(*parts));
		bytes_free(glue);
		if (admin == NULL)
			goto cleanup;
		/* reset the MD4 Intermediate Hash State */
		(void)memcpy(ctx.state, h, sizeof(ctx.state));
		/* extend the MD4 Intermediate Hash State */
		if (md4_hash_ctx(&ctx, extension) != 0)
			goto cleanup;
		digest = bytes_from_uint32_le(ctx.state, scount);
		if (digest == NULL)
			goto cleanup;
		const int ret = oracle(admin, digest);
		if (ret == -1) /* error */
			goto cleanup;
		if (ret == 0) /* success */
			break;
		bytes_free(admin);
		admin = NULL;
		bytes_free(digest);
		digest = NULL;
	}
	if (admin == NULL || digest == NULL)
		goto cleanup;

	if (msg_p != NULL) {
		*msg_p = admin;
		admin = NULL;
	}
	if (mac_p != NULL) {
		*mac_p = digest;
		digest = NULL;
	}

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(admin);
	bytes_free(digest);
	freezero(h, hcount * sizeof(uint32_t));
	bytes_free(extension);
	return (success ? 0 : -1);
}
#undef oracle


static struct bytes *
sha1_padding(size_t len)
{
	return padding(len, HIGH_WORD_FIRST_BE);
}


static struct bytes *
md4_padding(size_t len)
{
	return padding(len, LOW_WORD_FIRST_LE);
}


static struct bytes *
padding(size_t len, enum length_encoding le)
{
	/* max total message length, in bytes */
	struct bytes *padding = NULL;
	int success = 0;

	/* count of message bytes in the padded block */
	const size_t restlen = len % 64;
	/* count of padding bytes in the padded block */
	size_t padlen = 64 - restlen;
	if (padlen < (1 + 8)) {
		/* not enough space for the leading 0x80 and total message
		   length in the last block, add one block. */
		padlen += 64;
	}

	/* allocate enough space to hold the padding bytes */
	padding = bytes_zeroed(padlen);
	if (padding == NULL)
		goto cleanup;

	/* leading `1' bit */
	padding->data[0] = 0x80;

	/* set the 64-bits message length (count of bits) in the last 8 bytes of
	   the padded block */
	const uint64_t nbits = len * 8;
	size_t i = padlen - 8;
	switch (le) {
	case HIGH_WORD_FIRST_BE:
		padding->data[i++] = nbits >> 56;
		padding->data[i++] = nbits >> 48;
		padding->data[i++] = nbits >> 40;
		padding->data[i++] = nbits >> 32;
		padding->data[i++] = nbits >> 24;
		padding->data[i++] = nbits >> 16;
		padding->data[i++] = nbits >>  8;
		padding->data[i++] = nbits >>  0;
		break;
	case LOW_WORD_FIRST_LE:
		padding->data[i++] = nbits >>  0;
		padding->data[i++] = nbits >>  8;
		padding->data[i++] = nbits >> 16;
		padding->data[i++] = nbits >> 24;
		padding->data[i++] = nbits >> 32;
		padding->data[i++] = nbits >> 40;
		padding->data[i++] = nbits >> 48;
		padding->data[i++] = nbits >> 56;
		break;
	}

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		bytes_free(padding);
		padding = NULL;
	}
	return (padding);
}
