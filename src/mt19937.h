#ifndef MT19937_H
#define MT19937_H
/*
 * mt19937.h
 *
 * Mersenne Twister PRNG, see https://en.wikipedia.org/wiki/Mersenne_Twister
 */
#include <stdint.h>


/*
 * Initialize the PRNG with the given seed.
 */
void	mt19937_seed(uint32_t seed);

/*
 * Returns the next random number. If mt19937_seed() was not previously called,
 * it will be initialized with 5489 as the initial seed.
 */
uint32_t	mt19937_random_uint32(void);

#endif /* ndef MT19937_H */
