/*
 * break_repeating_key_xor.c
 *
 * Breaking Repeating-key XOR "cipher" (aka Vigenère cipher).
 */
#include <stdlib.h>

#include "compat.h"
#include "xor.h"
#include "break_single_byte_xor.h"
#include "break_repeating_key_xor.h"


/* simple struct used to represent a Repeating-key size and distance */
struct keysize_distance {
	size_t keysize;
	double distance;
};


/*
 * Comparing function for qsort(3). Sort keysize_distance based on their
 * distance in ascending order.
 */
static int	keysize_distance_cmp(const void *, const void *);

/*
 * Returns the Hamming distance for the given keysize in the provided buffer or
 * -1.0 on error.
 *
 * Uses the first three `keysize'-long slices from `buf'.
 */
static double	compute_keysize_distance(
		    const struct bytes *buf, size_t keysize);

/*
 * Attempt to break the given ciphertext assuming keysize. Returns NULL on
 * error.
 *
 * XXX: limited to english plaintext.
 */
static struct bytes	*break_known_keysize(const struct bytes *ciphertext,
		    size_t keysize, struct bytes **key_p, double *score_p);


struct bytes *
break_repeating_key_xor(const struct bytes *ciphertext,
		struct bytes **key_p, double *score_p)
{
	struct keysize_distance *kds = NULL;
	size_t kdslen = 0;
	struct bytes *decrypted = NULL, *key = NULL;
	double score = 0;
	int success = 0;

	/* sanity check */
	if (ciphertext == NULL)
		goto cleanup;

	/*
	 * Compute the maximum keysize we want to look for. We set an arbitrary
	 * upper limit to 40 hinted by the Set 1 / Challenge 6, but we want at
	 * least ten characters to give to break_single_byte_xor() because less
	 * than that is probably pointless. Thus, we divide by five because:
	 *   10 / 5 == 2 == `minkeysize'
	 */
	const size_t minkeysize = 2;
	size_t maxkeysize = (40 < ciphertext->len / 5 ?
		    40 : ciphertext->len / 5);
	if (maxkeysize < minkeysize) {
		/* we have less than ten characters to work with, it's not
		   worth a Repeating-key XOR analysis so we fallback to a
		   Single-byte XOR analysis. */
		return (break_single_byte_xor(ciphertext, looks_like_english, key_p, score_p));
	}
	const size_t nkeysize = maxkeysize - minkeysize + 1;

	/* Populate an array of keysize_distance for each keysize so that we can
	   then select the most interesting one. */
	kds = calloc(nkeysize, sizeof(struct keysize_distance));
	if (kds == NULL)
		goto cleanup;
	kdslen = nkeysize * sizeof(struct keysize_distance);
	for (size_t i = 0; i < nkeysize; i++) {
		const size_t keysize = minkeysize + i;
		const double d = compute_keysize_distance(ciphertext, keysize);
		if (d == -1)
			goto cleanup;
		kds[i].keysize = keysize;
		kds[i].distance = d;
	}

	/* sort the result so that the keysize with the smallest distances are
	   first in the array */
	qsort(kds, nkeysize, sizeof(struct keysize_distance),
		    keysize_distance_cmp);

	/* Try to break the key using the three keysize having yield the
	   smallest distance */
	const size_t iterations = (nkeysize < 3 ? nkeysize : 3);
	for (size_t i = 0; i < iterations; i++) {
		const size_t keysize = kds[i].keysize;
		struct bytes *idecrypted = NULL, *ikey = NULL;
		double iscore = 0;

		idecrypted = break_known_keysize(
			    ciphertext, keysize, &ikey, &iscore);
		if (idecrypted == NULL)
			goto cleanup;

		if (iscore > score) {
			bytes_free(decrypted);
			decrypted = idecrypted;
			bytes_free(key);
			key = ikey;
			score = iscore;
		} else {
			bytes_free(idecrypted);
			bytes_free(ikey);
		}
	}

	success = 1;

	/* set `key_p' and `score_p' if needed */
	if (key_p != NULL) {
		*key_p = key;
		key = NULL;
	}
	if (score_p != NULL)
		*score_p = score;

	/* FALLTHROUGH */
cleanup:
	bytes_free(key);
	freezero(kds, kdslen);
	if (!success) {
		bytes_free(decrypted);
		decrypted = NULL;
	}
	return (decrypted);
}


static int
keysize_distance_cmp(const void *va, const void *vb)
{
	const struct keysize_distance *a = va;
	const struct keysize_distance *b = vb;

	if (a->distance == b->distance)
		return (0);
	if (a->distance > b->distance)
		return (1);
	else
		return (-1);
}


static double
compute_keysize_distance(const struct bytes *buf, size_t keysize)
{
	double distance = -1;
	struct bytes *b0 = NULL, *b1 = NULL, *b2 = NULL;
	int success = 0;

	/* sanity checks */
	if (buf == NULL)
		goto cleanup;

	/* get the first three slice of keysize from buf */
	b0 = bytes_slice(buf, 0 * keysize, keysize);
	b1 = bytes_slice(buf, 1 * keysize, keysize);
	b2 = bytes_slice(buf, 2 * keysize, keysize);
	/* compute the hamming distance for each couple of slices */
	const intmax_t db0b1 = bytes_hamming_distance(b0, b1);
	const intmax_t db0b2 = bytes_hamming_distance(b0, b2);
	const intmax_t db1b2 = bytes_hamming_distance(b1, b2);
	if (db0b1 == -1 || db0b2 == -1 || db1b2 == -1)
		goto cleanup;

	/* average the computed distances */
	const double avg = db0b1 / 3.0 + db0b2 / 3.0 + db1b2 / 3.0;
	/* normalize the average wrt the keysize */
	distance = avg / keysize;

	/* we're done */
	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(b2);
	bytes_free(b1);
	bytes_free(b0);
	return (success ? distance : -1);
}


static struct bytes *
break_known_keysize(const struct bytes *ciphertext,
		    size_t keysize, struct bytes **key_p, double *score_p)
{
	struct bytes *decrypted = NULL, *key = NULL;
	uint8_t *keybuf = NULL;
	double score = 0;
	int success = 0;

	/* sanity check */
	if (ciphertext == NULL || keysize == 0)
		goto cleanup;

	/* we have a dedicated method (i.e. looks_like_english()) for the
	   special case keysize == 1 */
	if (keysize == 1) {
		return (break_single_byte_xor(ciphertext, looks_like_english, key_p, score_p));
	}

	/* Alloc and populate `keybuf' (our guess for the encryption key) one
	 * byte at a time */
	keybuf = calloc(keysize, sizeof(uint8_t));
	if (keybuf == NULL)
		goto cleanup;
	for (size_t offset = 0; offset < keysize; offset++) {
		struct bytes *slices, *ires, *ikey_p;
		/* filter only the ciphertext bytes having been XOR'd with the
		   current byte from the key */
		slices = bytes_slices(ciphertext, offset, 1, keysize - 1);
		/* NOTE: we can't use any heuristic depending on the byte order
		   here (e.g. english_word_lengths_freq()) because the selected
		   bytes from the ciphertext are not adjacent. */
		ikey_p = NULL;
		ires = break_single_byte_xor(slices, looks_like_shuffled_english, &ikey_p, NULL);
		if (ires == NULL || ikey_p == NULL || ikey_p->len != 1) {
			bytes_free(slices);
			goto cleanup;
		}
		/* finally populate `keybuf' */
		keybuf[offset] = ikey_p->data[0];
		/* cleanup */
		bytes_free(ikey_p);
		bytes_free(ires);
		bytes_free(slices);
	}

	/* build the guessed key and then decrypt the ciphertext with it */
	key = bytes_from_ptr(keybuf, keysize * sizeof(uint8_t));
	decrypted = bytes_dup(ciphertext);
	if (key == NULL || decrypted == NULL)
		goto cleanup;
	if (repeating_key_xor(decrypted, key) != 0)
		goto cleanup;

	/* if the score is requested, we can now try to run the full
	   analysis on the plaintext decrypted. This (hopefully) should yield a
	   more accurate result than the average of the scores for each key
	   byte. */
	if (score_p != NULL) {
		if (looks_like_english(decrypted, &score) != 0)
			goto cleanup;
	}

	success = 1;

	/* set `key_p' and `score_p' if needed */

	if (key_p != NULL) {
		*key_p = key;
		key = NULL;
	}
	if (score_p != NULL)
		*score_p = score;

	/* FALLTHROUGH */
cleanup:
	bytes_free(key);
	freezero(keybuf, keysize * sizeof(uint8_t));
	if (!success) {
		bytes_free(decrypted);
		decrypted = NULL;
	}
	return (decrypted);
}
