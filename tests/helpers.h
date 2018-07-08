#ifndef HELPERS_H
#define HELPERS_H
/*
 * helpers.h
 *
 * Some testing help stuff.
 */
#include "munit.h"
#include "bytes.h"

/*
 * Save a seed to be reused by srand_reset(). Call it once before all tests
 * suits start.
 */
void	init_seed(void);

/*
 * Call srand(3) with the seed that has been setup by init_seed().
 */
void	*srand_reset(const MunitParameter *params, void *user_data);

/*
 * Returns a random uint64_t value using munit_rand_uint32() twice.
 */
uint64_t	rand_uint64(void);

/*
 * Returns the content of the file at the given path, or NULL on error.
 */
struct bytes	*fs_read(const char *path);

#endif /* ndef HELPERS_H */
