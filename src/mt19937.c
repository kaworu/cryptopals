/*
 * mt19937.c
 *
 * Mersenne Twister PRNG, see https://en.wikipedia.org/wiki/Mersenne_Twister
 *
 * We follow religiously the pseudo-code from Wikipedia.
 */
#include <stdlib.h>

#include "compat.h"
#include "mt19937.h"

#define	w	32
#define	n	624
#define	m	397
#define	r	31
#define	a	0x9908b0df
#define	u	11
#define	d	0xffffffff
#define	s	7
#define	b	0x9d2c5680
#define	t	15
#define	c	0xefc60000
#define	l	18
#define	f	1812433253
#define	LOWEST_W_BITS_MASK	0xffffffff
#define	LOWER_MASK		0x7fffffff
#define	UPPER_MASK		0x80000000


/* generator struct definition */
struct mt19937_generator {
	uint32_t state[624];
	uint32_t index;
};


/* Generate the next n values from the series x_i */
static void	mt19937_twist(struct mt19937_generator *gen);


struct mt19937_generator *
mt19937_init(uint32_t seed)
{
	struct mt19937_generator *gen = NULL;
	int success = 0;

	gen = malloc(sizeof(struct mt19937_generator));
	if (gen == NULL)
		goto cleanup;

	if (mt19937_seed(gen, seed) != 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		mt19937_free(gen);
		gen = NULL;
	}
	return (gen);
}


int
mt19937_seed(struct mt19937_generator *gen, uint32_t seed)
{
	/* sanitity check */
	if (gen == NULL)
		return (-1);
	uint32_t *MT = gen->state;

	gen->index = n;
	MT[0] = LOWEST_W_BITS_MASK & seed;
	for (uint32_t i = 1; i < n; i++)
		MT[i] = LOWEST_W_BITS_MASK &
			    (f * (MT[i - 1] ^ (MT[i - 1] >> (w - 2))) + i);

	return (0);
}


int
mt19937_next_uint32(struct mt19937_generator *gen, uint32_t *n_p)
{
	/* sanitity check */
	if (gen == NULL)
		return (-1);
	uint32_t *MT = gen->state;

	if (gen->index >= n)
		mt19937_twist(gen);

	uint32_t y = MT[gen->index];
	y = y ^ ((y >> u) & d);
	y = y ^ ((y << s) & b);
	y = y ^ ((y << t) & c);
	y = y ^ (y >> l);

	gen->index = gen->index + 1;

	if (n_p != NULL)
		*n_p = (LOWEST_W_BITS_MASK & y);
	return (0);
}


void
mt19937_free(struct mt19937_generator *gen)
{
	freezero(gen, sizeof(struct mt19937_generator));
}


static void
mt19937_twist(struct mt19937_generator *gen)
{
	uint32_t *MT = gen->state;

	for (uint32_t i = 0; i < n; i++) {
		const uint32_t x = (MT[i] & UPPER_MASK) +
			    (MT[(i + 1) % n] & LOWER_MASK);
		uint32_t xA = x >> 1;
		if ((x % 2) != 0) /* lowest bit of x is 1 */
			xA = xA ^ a;
		MT[i] = MT[(i + m) % n] ^ xA;
	}
	gen->index = 0;
}
