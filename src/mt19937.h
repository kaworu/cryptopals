#ifndef MT19937_H
#define MT19937_H
/*
 * mt19937.h
 *
 * Mersenne Twister PRNG, see https://en.wikipedia.org/wiki/Mersenne_Twister
 */
#include "bytes.h"


/*
 * MT19937 PRNG generator struct.
 */
struct mt19937_generator;


/*
 * Returns a new MT19937 generator initialized with the given seed that should
 * be passed to mt19937_free(), or NULL if malloc(3) failed.
 */
struct mt19937_generator	*mt19937_init(uint32_t seed);

/*
 * Returns a new MT19937 generator initialized with the given internal state and
 * index that should be passed to mt19937_free(), or NULL on failure.
 *
 * The provided state should be an array of 624 uint32_t values.
 */
struct mt19937_generator	*mt19937_from_state(
		    const uint32_t *state, uint32_t index);

/*
 * Reinitialize the given MT19937 generator with the provided seed value.
 * Returns 0 on success, -1 if gen is NULL.
 */
int	mt19937_seed(struct mt19937_generator *gen, uint32_t seed);

/*
 * Generate the provided generator's next random number and store it in n_p if
 * it is not NULL. Returns 0 on success, -1 if gen is NULL.
 */
int	mt19937_next_uint32(struct mt19937_generator *gen, uint32_t *n_p);

/*
 * Free the resource associated with the given mt19937_generator struct.
 *
 * If not NULL, the generator state will be zero'd before freed.
 */
void	mt19937_free(struct mt19937_generator *gen);

#endif /* ndef MT19937_H */
