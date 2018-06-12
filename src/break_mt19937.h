#ifndef BREAK_MT19937_H
#define BREAK_MT19937_H
/*
 * break_mt19937.h
 *
 * MT19937 analysis stuff for cryptopals.com challenges.
 */
#include <stdint.h>


/*
 * Wait between 40 and 1000 seconds before seeding MT19937 with the current UNIX
 * timestamp. Then, wait again between 40 and 1000 seconds before returning.
 *
 * Return the first 32 bits output of MT19937 after it has been seeded.
 *
 * If now_p is not NULL, it is considered as the current UNIX timestamp and
 * computation will be done instead of actual waiting. Once
 * mt19937_time_seed_oracle() returns, now_p is set to the UNIX timestamp that
 * would be the current one if sleep(2) whould have been called.
 *
 * If seed_p is not NULL it will be set to the value used as the initial seed
 * for MT19937.
 */
uint32_t	mt19937_time_seed_oracle(uint32_t *now_p, uint32_t *seed_p);

/*
 * Returns the seed used to intialize MT19937 when its 32 bits of output is
 * `generated' and seed is between `before' and `after' (included).
 */
uint32_t	mt19937_time_seed_breaker(uint32_t before, uint32_t after,
		    uint32_t generated);

#endif /* ndef BREAK_MT19937_H */
