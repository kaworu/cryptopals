#ifndef HELPERS_H
#define HELPERS_H
/*
 * helpers.h
 *
 * Some testing help stuff.
 */
#include "munit.h"

/*
 * Save a seed to be reused by srand_reset(). Call it once before all tests
 * suits start.
 */
void	init_seed(void);

/*
 * Call srand(3) with the seed that has been setup by init_seed().
 */
void	*srand_reset(const MunitParameter *params, void *user_data);

#endif /* ndef HELPERS_H */
