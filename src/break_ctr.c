/*
 * break_ctr.c
 *
 * CTR analysis stuff for cryptopals.com challenges.
 */

#include "compat.h"
#include "xor.h"
#include "ctr.h"
#include "break_ctr.h"
#include "break_single_byte_xor.h"


struct bytes *
break_ctr_fixed_nonce(struct bytes **ciphertexts, size_t count)
{
	struct bytes *keystream = NULL;
	int success = 0;

	/* sanity checks */
	if (ciphertexts == NULL || count == 0)
		goto cleanup;

	/* find the length of the longest ciphertext(s) */
	size_t maxlen = 0;
	for (size_t i = 0; i < count; i++) {
		const struct bytes *ciphertext = ciphertexts[i];
		if (ciphertext == NULL)
			goto cleanup;
		maxlen = (ciphertext->len > maxlen ? ciphertext->len : maxlen);
	}

	keystream = bytes_zeroed(maxlen);
	if (keystream == NULL)
		goto cleanup;

	/* break the keystream one byte at a time */
	for (size_t i = 0; i < maxlen; i++) {
		struct bytes *buf = NULL, *key = NULL;
		/* we will aggregate the ith byte of each ciphertext. Start by
		   computing the length of the buffer */
		size_t buflen = 0;
		for (size_t j = 0; j < count; j++) {
			/* check that the current ciphertext is long enough to
			   hold a byte at i */
			if (ciphertexts[j]->len > i)
				buflen += 1;
		}
		/* Now that we know the length, allocate the buffer */
		buf = bytes_zeroed(buflen);
		if (buf == NULL)
			goto cleanup;
		/* populate the buffer with the ith byte of each ciphertext */
		buflen = 0;
		for (size_t j = 0; j < count; j++) {
			if (ciphertexts[j]->len > i) {
				buf->data[buflen++] = ciphertexts[j]->data[i];
			}
		}

		/* attempt to guess the ith keystream byte */
		struct bytes *result = break_single_byte_xor(
			    buf, looks_like_shuffled_english, &key, NULL);
		bytes_free(buf);
		if (result == NULL)
			goto cleanup;
		bytes_free(result);
		if (key == NULL || key->len != 1) {
			bytes_free(key);
			goto cleanup;
		}
		keystream->data[i] = key->data[0];
		bytes_free(key);
	}

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		bytes_free(keystream);
		keystream = NULL;
	}
	return (keystream);
}


struct bytes *
aes_128_ctr_edit_oracle(const struct bytes *ciphertext,
		    const struct bytes *key, uint64_t nonce,
		    size_t offset, const struct bytes *replacement)
{
	struct bytes *zeroes = NULL, *keystream = NULL, *rkeystream = NULL;
	struct bytes *before = NULL, *rct = NULL, *after = NULL, *output = NULL;
	int success = 0;

	/* sanity checks */
	if (ciphertext == NULL || key == NULL || replacement == NULL)
		goto cleanup;
	if (offset > ciphertext->len)
		goto cleanup;
	if (ciphertext->len - offset < replacement->len)
		goto cleanup;

	/*
	 * We build the output as:
	 *
	 *    before  offset  rct   bound  after
	 *       v      |      v      |      v
	 * [ ......... ][ .......... ][ .......... ]
	 *
	 * Here rct is the "replacement ciphertext", i.e. the encrypted version
	 * of replacement. before and after are untouched slices of the original
	 * ciphertext.
	 */

	const size_t bound = offset + replacement->len;

	/* encrypt as many 0x0 as we need in order to get the keystream */
	zeroes = bytes_zeroed(bound);
	keystream = aes_128_ctr_encrypt(zeroes, key, nonce);
	/* get the part of the keystream needed to encrypt the replacement */
	rkeystream = bytes_slice(keystream, offset, replacement->len);
	rct = bytes_dup(replacement);
	if (bytes_xor(rct, rkeystream) != 0)
		goto cleanup;

	/* find the copied parts from the ciphertext before and after the
	   replacement */
	before = bytes_slice(ciphertext, 0, offset);
	after = bytes_slice(ciphertext, bound, ciphertext->len - bound);
	const struct bytes *const parts[] = { before, rct, after };
	output = bytes_joined_const(parts, sizeof(parts) / sizeof(*parts));

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(after);
	bytes_free(before);
	bytes_free(rct);
	bytes_free(rkeystream);
	bytes_free(keystream);
	bytes_free(zeroes);
	if (!success) {
		bytes_free(output);
		output = NULL;
	}
	return (output);
}


struct bytes *
aes_128_ctr_edit_breaker(const struct bytes *ciphertext,
		    const struct bytes *key, const uint64_t nonce)
#define oracle(ct, off, rep) \
		aes_128_ctr_edit_oracle((ct), key, nonce, (off), (rep))
{
	return (oracle(ciphertext, 0, ciphertext));
}
#undef oracle
