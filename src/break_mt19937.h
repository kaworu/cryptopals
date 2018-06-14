#ifndef BREAK_MT19937_H
#define BREAK_MT19937_H
/*
 * break_mt19937.h
 *
 * MT19937 analysis stuff for cryptopals.com challenges.
 */
#include "mt19937.h"


/*
 * Wait between 40 and 1000 seconds before seeding the given generator with the
 * current UNIX timestamp. Then, wait again between 40 and 1000 seconds before
 * returning.
 *
 * if n_p is not NULL, it is set to the first 32 bits output of the generator
 * after it has been seeded (consequently, the generator will be advanced by 32
 * bits).
 *
 * If now_p is not NULL, it is considered as the current UNIX timestamp and
 * computation will be done instead of actual waiting. Once
 * mt19937_time_seeder() returns, now_p is set to the UNIX timestamp that would
 * be the current one if sleep(2) whould have been called.
 *
 * If seed_p is not NULL it will be set to the value used as the initial seed
 * for MT19937.
 *
 * Returns 0 on success, -1 if gen is NULL.
 */
int	mt19937_time_seeder(struct mt19937_generator *gen,
		    uint32_t *n_p, uint32_t *now_p, uint32_t *seed_p);

/*
 * Compute the seed used to intialize a MT19937 generator when its first 32 bits
 * of output is `generated' and it has been seeded with a value between `before'
 * and `after' (included).
 *
 * If seed_p is not NULL, it is set to the guessed seed value.
 *
 * Returns 0 on success, 1 on failure, and -1 on error.
 */
int	mt19937_time_seeder_breaker(uint32_t before, uint32_t after,
		    uint32_t generated, uint32_t *seed_p);

/*
 * Return a generator that should produce the same random sequence as the given
 * one, NULL on error. The provided generator should have been (re)seeded before
 * calling mt19937_clone() without having generated any number in between, and
 * will be advanced 624 times.
 */
struct mt19937_generator	*mt19937_clone(struct mt19937_generator *gen);

/*
 * Compute the 16 bits key given a full ciphertext and the known bits of
 * plaintext as described in Set 3 / Challenge 24. Returns 0 on success, -1 on
 * failure.
 *
 * If key_p is not NULL it will be set to the guessed key on success.
 */
int	mt19937_encryption_breaker(const struct bytes *ciphertext,
		    const struct bytes *known_plaintext, uint16_t *key_p);

/*
 * Guess if the given token is a MT19937 output seeded with the current time in
 * the last hour.
 *
 * Returns 0 on success if the token is valid, 1 if the token is invalid, -1 on
 * error.
 */
int	mt19937_token_breaker(const uint32_t *token, size_t tokenlen);

#endif /* ndef BREAK_MT19937_H */
