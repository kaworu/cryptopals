/*
 * break_mt19937.c
 *
 * MT19937 analysis stuff for cryptopals.com challenges.
 */
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "mt19937.h"
#include "break_mt19937.h"


uint32_t
mt19937_time_seed_oracle(uint32_t *now_p, uint32_t *seed_p)
{
	uint32_t seed;
	const uint32_t before_delay = 40 + rand() % (1000 - 40);
	const uint32_t after_delay  = 40 + rand() % (1000 - 40);

	if (now_p != NULL) {
		seed = *now_p + before_delay;
		*now_p = seed + after_delay;
	} else {
		sleep(before_delay);
		seed = time(NULL);
		sleep(after_delay);
	}

	if (seed_p != NULL)
		*seed_p = seed;

	mt19937_seed(seed);
	return (mt19937_random_uint32());
}


uint32_t
mt19937_time_seed_breaker(uint32_t before, uint32_t after, uint32_t generated)
{
	uint32_t i;

	for (i = before; i <= after; i++) {
		mt19937_seed(i);
		const uint32_t n = mt19937_random_uint32();
		if (n == generated)
			break;
	}

	return (i);
}
