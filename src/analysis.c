/*
 * analysis.c
 *
 * Plain text analysis stuff for cryptopals.com challenges.
 */
#include <ctype.h>
#include <math.h>

#include "analysis.h"


/* english character frequency, taken from http://norvig.com/mayzner.html */
static const double english_freq[26] = {
	/* 'a' */  8.04,
	/* 'b' */  1.48,
	/* 'c' */  3.34,
	/* 'd' */  3.82,
	/* 'e' */ 12.49,
	/* 'f' */  2.40,
	/* 'g' */  1.87,
	/* 'h' */  5.05,
	/* 'i' */  7.57,
	/* 'j' */  0.16,
	/* 'k' */  0.54,
	/* 'l' */  4.07,
	/* 'm' */  2.51,
	/* 'n' */  7.23,
	/* 'o' */  7.64,
	/* 'p' */  2.14,
	/* 'q' */  0.12,
	/* 'r' */  6.28,
	/* 's' */  6.51,
	/* 't' */  9.28,
	/* 'u' */  2.73,
	/* 'v' */  1.05,
	/* 'w' */  1.68,
	/* 'x' */  0.23,
	/* 'y' */  1.66,
	/* 'z' */  0.09,
};


/*
 * Returns the character frequency match in the given bytes struct using
 * freq_ref as reference.
 *
 * Returns -1.0 if either argument is NULL.
 */
double	analysis_char_freq(const struct bytes *buf, const double *freq_ref);


/* NOTE: very naive using only character frequency stats. Could be improved by
   analysing words etc. */
double
analysis_looks_like_english(const struct bytes *buf)
{
	return analysis_char_freq(buf, english_freq);
}


/* NOTE: this algorithm could be improved by computing the byte frequency only
   once (yielding an offset and checking for the result). The current
   implementation test each byte which is 255 times slower (!) but OTHO doesn't
   depend on the analysis_looks_like_english implementation. */
struct bytes *
analysis_single_byte_xor(const struct bytes *buf, double *p)
{
	struct bytes *ret = NULL;
	uint8_t guess = 0;
	uint8_t k, pk;
	double gprob = 0;
	int success = 0;

	/* create a working copy of the buffer to analyze */
	ret = bytes_copy(buf);
	if (ret == NULL)
		goto out;

	/* previous key used */
	pk = 0;
	/* go through each possible byte and find the one most likely to yield
	   english text */
	for (k = 0; k < UINT8_MAX; k++) {
		/* XOR the working buffer with the previous key and the current
		   key, so that we undo the last encrypt iteration and encrypt
		   for the current iteration at once.  */
		for (size_t i = 0; i < ret->len; i++)
			ret->data[i] ^= (k ^ pk);
		/* run the analysis on the "decrypted" buffer */
		double p = analysis_looks_like_english(ret);
		/* save the current analysis if it looks like the best one */
		if (p > gprob) {
			guess = k;
			gprob = p;
		}
		/* setup the previous key to be the current one for the next
		   iteration */
		pk = k;
	}

	/* here `guess' is our guessed key and `gprob' the probability that is
	   this the correct one. The working buffer is encrypted with `k' from
	   the last loop iteration */
	for (size_t i = 0; i < ret->len; i++)
		ret->data[i] ^= (guess ^ pk);

	success = 1;
	/* FALLTHROUGH */
out:
	if (success) {
		if (p != NULL)
			*p = gprob;
	} else {
		free(ret);
		ret = NULL;
	}

	return (ret);
}


double
analysis_char_freq(const struct bytes *buf, const double *freq_ref)
{
	double prob = 0;
	double freqs[26] = { 0 };

	/* sanity check */
	if (buf == NULL || freq_ref == NULL)
		return (-1);
	if (buf->len == 0)
		return (0);

	/* the increment when a character is seen */
	const double inc = 1.0 / buf->len;

	/* populate freqs by inspecting the buffer */
	for (size_t i = 0; i < buf->len; i++) {
		uint8_t byte = buf->data[i];
		if (byte >= 'a' && byte <= 'z' || byte >= 'A' && byte <= 'Z')
			freqs[tolower(byte) - 'a'] += inc;
	}

	/*
	 * compute the difference between the reference frequencies and the
	 * aggregated ones.
	 */
	for (size_t i = 0; i < 26; i++) {
		double ref = freq_ref[i];
		double actual = freqs[i];
		double delta = fabs(ref - actual);
		prob += (ref - delta);
	}

	return (prob);
}
