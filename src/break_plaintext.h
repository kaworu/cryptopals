#ifndef BREAK_PLAINTEXT_H
#define BREAK_PLAINTEXT_H
/*
 * break_plaintext.h
 *
 * Plain text analysis stuff for cryptopals.com challenges.
 */
#include "bytes.h"


/*
 * Function type to analyze a given buffer, set the score and returns 0 on
 * success, -1 on failure.
 */
typedef int (break_plaintext_func_t)(const struct bytes *buf, double *score_p);

/*
 * Provide the score of the given buffer as plaintext english.
 */
int	looks_like_english(const struct bytes *buf, double *score_p);

/*
 * Provide the score of the given buffer as shuffled plaintext english
 * (characters don't have to be in order).
 */
int	looks_like_shuffled_english(const struct bytes *buf, double *score_p);

/*
 * Provide the score of the given buffer as having the same character frequency
 * than english plaintext.
 *
 * This function should yield the same score regardless of the byte order in the
 * given buffer, while looks_like_english() may perform other kind of analysis
 * like pair of character frequency, words length frequency etc.
 */
int	english_char_freq(const struct bytes *buf, double *score_p);

/*
 * Provide the score of the given buffer as having the same word lengths
 * frequency as english plaintext.
 */
int	english_word_lengths_freq(const struct bytes *buf, double *score_p);

/*
 * Provide the score of the given buffer as ascii plaintext.
 *
 * See https://en.wikipedia.org/wiki/ASCII#Printable_characters
 */
int	mostly_ascii(const struct bytes *buf, double *score_p);

#endif /* ndef BREAK_PLAINTEXT_H */
