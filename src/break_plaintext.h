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

#endif /* ndef BREAK_PLAINTEXT_H */
