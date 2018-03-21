/*
 * break_single_byte_xor.c
 *
 * Breaking Single-byte XOR "cipher".
 */
#include "break_plaintext.h"
#include "break_single_byte_xor.h"


/* NOTE: this algorithm could be improved by computing the byte frequency only
   once (yielding an offset and checking for the result). The current
   implementation test each byte which is 255 times slower (!) but OTHO doesn't
   depend on the looks_like_english() implementation. */
struct bytes *
break_single_byte_xor(const struct bytes *ciphertext,
		struct bytes **key_p, double *score_p)
{
	struct bytes *xored = NULL;
	uint8_t guess = 0;
	double gprob = 0;
	int success = 0;

	/* sanity check */
	if (ciphertext == NULL)
		goto out;

	/* create a working copy of the buffer to analyze */
	xored = bytes_dup(ciphertext);
	if (xored == NULL)
		goto out;

	/* previous key used */
	uint8_t pk = 0;
	/* go through each possible byte and find the one most likely to yield
	   english text */
	for (uint8_t k = 0; k < UINT8_MAX; k++) {
		/* XOR the working buffer with the previous key and the current
		   key, so that we undo the last encrypt iteration and encrypt
		   for the current iteration at once.  */
		for (size_t i = 0; i < xored->len; i++)
			xored->data[i] ^= (k ^ pk);
		/* run the analysis on the "decrypted" buffer */
		double p = looks_like_english(xored);
		/* save the current guess if it looks like the best one */
		if (p > gprob) {
			guess = k;
			gprob = p;
		}
		/* setup the previous key to be the current one for the next
		   iteration */
		pk = k;
	}

	/* here `guess' is our guessed key and `gprob' the probability that is
	   this the correct one. The working buffer is encrypted with `pk' from
	   the last loop iteration */
	for (size_t i = 0; i < xored->len; i++)
		xored->data[i] ^= (guess ^ pk);

	/* set `key_p' and `score_p' if needed */
	if (key_p != NULL) {
		struct bytes *key = bytes_from_single(guess);
		if (key == NULL)
			goto out;
		*key_p = key;
	}
	if (score_p != NULL)
		*score_p = gprob;

	success = 1;
	/* FALLTHROUGH */
out:
	if (!success) {
		free(xored);
		xored = NULL;
	}
	return (xored);
}
