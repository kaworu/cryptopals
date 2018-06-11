/*
 * mt19937.c
 *
 * Mersenne Twister PRNG, see https://en.wikipedia.org/wiki/Mersenne_Twister
 *
 * We follow religiously the pseudo-code from Wikipedia, except that we seed
 * with a default value when mt19937_random_uint32() is called and the generator
 * is not seeded.
 */
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


static uint32_t MT[n];
static uint32_t index = n + 1;


/* Generate the next n values from the series x_i */
static void	mt19937_twist(void);


void
mt19937_seed(uint32_t seed)
{
	index = n;
	MT[0] = LOWEST_W_BITS_MASK & seed;
	for (uint32_t i = 1; i < n; i++)
		MT[i] = LOWEST_W_BITS_MASK &
			    (f * (MT[i - 1] ^ (MT[i - 1] >> (w - 2))) + i);
}


uint32_t
mt19937_random_uint32(void)
{
	if (index >= n) {
		if (index > n) {
			/* use a default initial seed as the reference
			   implementation */
			mt19937_seed(5489);
		}
		mt19937_twist();
	}

	uint32_t y = MT[index];
	y = y ^ ((y >> u) & d);
	y = y ^ ((y << s) & b);
	y = y ^ ((y << t) & c);
	y = y ^ (y >> l);

	index = index + 1;
	return (LOWEST_W_BITS_MASK & y);
}


static void
mt19937_twist(void)
{
	for (uint32_t i = 0; i < n; i++) {
		const uint32_t x = (MT[i] & UPPER_MASK) +
			    (MT[(i + 1) % n] & LOWER_MASK);
		uint32_t xA = x >> 1;
		if ((x % 2) != 0) /* lowest bit of x is 1 */
			xA = xA ^ a;
		MT[i] = MT[(i + m) % n] ^ xA;
	}
	index = 0;
}
