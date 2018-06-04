/*
 * break_ctr.c
 *
 * CTR analysis stuff for cryptopals.com challenges.
 */

#include "compat.h"
#include "xor.h"
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
			    buf, english_char_freq, &key, NULL);
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
