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


int
mt19937_time_seeder(struct mt19937_generator *gen,
		    uint32_t *n_p, uint32_t *now_p, uint32_t *seed_p)
{
	uint32_t seed, n;
	const uint32_t before_delay = 40 + rand() % (1000 - 40);
	const uint32_t after_delay  = 40 + rand() % (1000 - 40);
	int success = 0;

	/* sanitity check */
	if (gen == NULL)
		goto cleanup;

	/* seed generation */
	if (now_p != NULL) {
		seed = *now_p + before_delay;
	} else {
		sleep(before_delay);
		seed = time(NULL);
		sleep(after_delay);
	}

	/* initialize the generator with the seed */
	if (mt19937_seed(gen, seed) != 0)
		goto cleanup;

	/* get the first 32 bits of output */
	if (mt19937_next_uint32(gen, &n) != 0)
		goto cleanup;

	if (n_p != NULL)
		*n_p = n;
	if (now_p != NULL)
		*now_p = seed + after_delay;
	if (seed_p != NULL)
		*seed_p = seed;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	return (success ? 0 : -1);
}


int
mt19937_time_seeder_breaker(uint32_t before, uint32_t after, uint32_t generated,
		    uint32_t *seed_p)
{
	struct mt19937_generator *gen = NULL;
	uint32_t seed = 0;
	int found = 0, success = 0;

	gen = mt19937_init(0);
	if (gen == NULL)
		goto cleanup;

	for (seed = before; seed <= after; seed++) {
		uint32_t n = 0;
		if (mt19937_seed(gen, seed) != 0)
			goto cleanup;
		if (mt19937_next_uint32(gen, &n) != 0)
			goto cleanup;
		if (n == generated)
			break;
	}
	found = (seed <= after);

	if (found && seed_p != NULL)
		*seed_p = seed;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	mt19937_free(gen);
	if (!success)
		return (-1);
	return (found ? 0 : 1);
}
