/*
 * break_plaintext.c
 *
 * Plain text analysis stuff for cryptopals.com challenges.
 */
#include "break_plaintext.h"


/*
 * Provide the character frequency match in the given bytes struct using
 * `freq_ref' as reference.
 *
 * `freq_ref' is an array used to represent characters frequency using only the
 * letters 'a' to 'z' in a case-insensitive fashion. Note that it must be an
 * array of size 27 with index 0 being for the letter `a' (case-insensitive)
 * until index 25 for the letter 'z' (case-insensitive) and the special index 26
 * for the space (i.e. ' ') character.
 *
 * Returns 0 on success, -1 on failure.
 */
static int	char_freq(const struct bytes *buf, const double *freq_ref,
		    double *score);

/*
 * Provide the word lengths match in the given bytes struct using `freq_ref' as
 * reference.
 *
 * `freq_ref' is an array used to represent word lengths frequency.  Note that
 * it must be an array of size 11 with index 0 being for the word lengths of one
 * until index 9 for the word lengths of 10 and the special index 11 for "more
 * than ten characters long".
 *
 * Returns 0 on success, -1 on failure.
 */
static int	word_lengths_freq(const struct bytes *buf,
		    const double *freq_ref, double *score);



/* NOTE: very naive using only some basic character and word lengths
   frequencies. Could be improved by analysing words etc. */
int
looks_like_english(const struct bytes *buf, double *score)
{
	double chars = 0, words = 0;
	int success = 0;

	/* sanity checks */
	if (buf == NULL || score == NULL)
		goto cleanup;

	if (english_char_freq(buf, &chars) != 0)
		goto cleanup;
	if (english_word_lengths_freq(buf, &words) != 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (success) {
		*score = (chars * 0.5 + words * 0.5);
	}
	return (success ? 0 : -1);
}


int
english_char_freq(const struct bytes *buf, double *score)
{
	/* Some english character frequency, taken from
	   http://www.fitaly.com/board/domper3/posts/136.html */
	static const double english_char_freq_table[27] = {
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

	return char_freq(buf, english_char_freq_table, score);
}


int
english_word_lengths_freq(const struct bytes *buf, double *score)
{
	/* Some english word lengths , taken from
	   http://norvig.com/mayzner.html */
	static const double english_word_lengths_freq_table[11] = {
		/* len =  1 */  2.998,
		/* len =  2 */ 17.651,
		/* len =  3 */ 20.511,
		/* len =  4 */ 14.787,
		/* len =  5 */ 10.700,
		/* len =  6 */  8.388,
		/* len =  7 */  7.939,
		/* len =  8 */  5.943,
		/* len =  9 */  4.437,
		/* len = 10 */  3.076,
		/* len = 11 */  1.761 +
		/* len = 12 */  0.958 +
		/* len = 13 */  0.518 +
		/* len = 14 */  0.222 +
		/* len = 15 */  0.076 +
		/* len = 16 */  0.020 +
		/* len = 17 */  0.010 +
		/* len = 18 */  0.004 +
		/* len = 19 */  0.001 +
		/* len = 20 */  0.001
	};

	return word_lengths_freq(buf, english_word_lengths_freq_table, score);
}


static int
char_freq(const struct bytes *buf, const double *freq_ref, double *score)
{
	size_t count[27] = { 0 }; /* FIXME: that 27 need a #define */
	int success = 0;

	/* sanity checks */
	if (buf == NULL || freq_ref == NULL || score == NULL)
		goto cleanup;

	size_t skipped = 0;
	/* populate count by inspecting the buffer */
	for (size_t i = 0; i < buf->len; i++) {
		const uint8_t byte = buf->data[i];
		if (byte >= 'a' && byte <= 'z')
			count[byte - 'a'] += 1;
		else if (byte >= 'A' && byte <= 'Z')
			count[byte - 'A'] += 1;
		else if (byte == ' ')
			count[26] += 1;
		else
			skipped += 1;
	}

	/*
	 * compute the difference between the reference frequencies and the
	 * aggregated ones.
	 *
	 * FIXME: extract in a function, copy/pasta at word_lengths_freq().
	 */
	*score = 0;
	if (buf->len > 0) {
		const double factor = 100.0 / buf->len;
		for (int i = 0; i < (sizeof(count) / sizeof(*count)); i++) {
			const double ref = freq_ref[i];
			const double actual = count[i] * factor;
			const double delta = ref - actual;
			*score += ref - (delta < 0 ? -delta : delta);
		}
	}

	success = 1;
	/* FALLTHROUGH */
cleanup:
	return (success ? 0 : -1);
}


static int
word_lengths_freq(const struct bytes *buf, const double *freq_ref,
		double *score)
{
	size_t count[11] = { 0 }; /* FIXME: that 11 need a #define */
	int success = 0;

	/* sanity checks */
	if (buf == NULL || freq_ref == NULL || score == NULL)
		goto cleanup;

	/* total word count */
	size_t wc = 0;
	/* current word length, zero mean we're not in a word */
	size_t wlen = 0;
	/* populate count by inspecting the buffer */
	for (size_t i = 0; i < buf->len; i++) {
		const uint8_t byte = buf->data[i];
		const int islower = (byte >= 'a' && byte <= 'z');
		const int isupper = (byte >= 'A' && byte <= 'Z');
		if (islower || isupper) {
			/* we're inside a word, increment the current
			   word length and the total word count if we're just
			   starting this word */
			wc += (wlen == 0);
			wlen += 1;
		} else if (wlen > 0) {
			/* we're at the end of a word */
			count[wlen > 10 ? 10 : wlen - 1] += 1;
			wlen = 0;
		}
	}

	/*
	 * compute the difference between the reference frequencies and the
	 * aggregated ones.
	 *
	 * FIXME: extract in a function, copy/pasta from char_freq().
	 */
	*score = 0;
	if (wc > 0) {
		const double factor = 100.0 / wc;
		for (int i = 0; i < (sizeof(count) / sizeof(*count)); i++) {
			const double ref = freq_ref[i];
			const double actual = count[i] * factor;
			const double delta = ref - actual;
			*score += ref - (delta < 0 ? -delta : delta);
		}
	}

	success = 1;
	/* FALLTHROUGH */
cleanup:
	return (success ? 0 : -1);
}
