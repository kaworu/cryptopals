#ifndef BREAK_PLAINTEXT_H
#define BREAK_PLAINTEXT_H
/*
 * break_plaintext.h
 *
 * Plain text analysis stuff for cryptopals.com challenges.
 */
#include "bytes.h"


/*
 * Returns the score of the given buffer as plaintext english, -1.0 if the
 * provided bytes struct argument is NULL.
 */
double	looks_like_english(const struct bytes *buf);

/*
 * Returns the score of the given buffer as having the same character frequency
 * than english plaintext, -1.0 if the provided bytes struct argument is NULL.
 *
 * This function should return the same score regardless of the byte order in
 * the given buffer, while looks_like_english() may perform other kind of
 * analysis like pair of character frequency, words length frequency etc.
 */
double	english_char_freq(const struct bytes *buf);

/*
 * Returns the score of the given buffer as having the same word lengths
 * frequency as english plaintext, -1.0 if the provided bytes struct argument is
 * NULL.
 */
double	english_word_lengths_freq(const struct bytes *buf);

#endif /* ndef BREAK_PLAINTEXT_H */
