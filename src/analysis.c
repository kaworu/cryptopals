/*
 * analysis.c
 *
 * Plain text analysis stuff for cryptopals.com challenges.
 */
#include <math.h>

#include "analysis.h"


/* Some english character frequency, taken from http://www.fitaly.com/board/domper3/posts/136.html */
static const double english_freq[27] = {
	/* A */  0.3132 + /* a */  5.1880,
	/* B */  0.2163 + /* b */  1.0195,
	/* C */  0.3906 + /* c */  2.1129,
	/* D */  0.3151 + /* d */  2.5071,
	/* E */  0.2673 + /* e */  8.5771,
	/* F */  0.1416 + /* f */  1.3725,
	/* G */  0.1876 + /* g */  1.5597,
	/* H */  0.2321 + /* h */  2.7444,
	/* I */  0.3211 + /* i */  4.9019,
	/* J */  0.1726 + /* j */  0.0867,
	/* K */  0.0687 + /* k */  0.6753,
	/* L */  0.1884 + /* l */  3.1750,
	/* M */  0.3529 + /* m */  1.6437,
	/* N */  0.2085 + /* n */  4.9701,
	/* O */  0.1842 + /* o */  5.7701,
	/* P */  0.2614 + /* p */  1.5482,
	/* Q */  0.0316 + /* q */  0.0747,
	/* R */  0.2519 + /* r */  4.2586,
	/* S */  0.4003 + /* s */  4.3686,
	/* T */  0.3322 + /* t */  6.3700,
	/* U */  0.0814 + /* u */  2.0999,
	/* V */  0.0892 + /* v */  0.8462,
	/* W */  0.2527 + /* w */  1.3034,
	/* X */  0.0343 + /* x */  0.1950,
	/* Y */  0.0304 + /* y */  1.1330,
	/* Z */  0.0076 + /* z */  0.0596,
	/* space */ 17.1662,
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
	double freqs[27] = { 0 };

	/* sanity checks */
	if (buf == NULL || freq_ref == NULL)
		return (-1);
	if (buf->len == 0)
		return (0);

	/* populate freqs by inspecting the buffer */
	for (size_t i = 0; i < buf->len; i++) {
		const uint8_t byte = buf->data[i];
		if (byte >= 'a' && byte <= 'z')
			freqs[byte - 'a'] += 1.0 / buf->len;
		else if (byte >= 'A' && byte <= 'Z')
			freqs[byte - 'A'] += 1.0 / buf->len;
		else if (byte == ' ')
			freqs[26] += 1.0 / buf->len;
	}

	/*
	 * compute the difference between the reference frequencies and the
	 * aggregated ones.
	 */
	for (int i = 0; i < 27; i++) {
		const double ref = freq_ref[i];
		const double actual = freqs[i];
		const double delta = fabs(ref - actual);
		if (delta < ref)
			prob += (ref - delta);
	}

	return (prob);
}
