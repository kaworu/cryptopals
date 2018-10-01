/*
 * helpers.c
 *
 * Some testing help stuff.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>


#include "helpers.h"


static unsigned int seed = 0;


void
init_seed(void)
{
	static int initialized = 0;

	if (!initialized) {
		seed = munit_rand_uint32();
		initialized = 1;
	}
}


void *
srand_reset(const MunitParameter *params, void *user_data)
{
	init_seed();
	srand(seed);
	return (NULL);
}


uint64_t
rand_uint64(void)
{
	uint64_t lo = munit_rand_uint32();
	uint64_t hi = munit_rand_uint32();
	return ((hi << 32) | lo);
}


struct bytes *
fs_read(const char *path)
{
	struct stat st;
	struct bytes *content = NULL;
	int fd = -1;
	int success = 0;

	if (path == NULL)
		goto cleanup;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		goto cleanup;

	if (fstat(fd, &st) == -1)
		goto cleanup;

	content = bytes_zeroed(st.st_size);
	if (content == NULL)
		goto cleanup;

	ssize_t ret = read(fd, content->data, content->len);
	if (ret == -1 || (size_t)ret != content->len)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	(void)close(fd);
	if (!success) {
		bytes_free(content);
		content = NULL;
	}
	return (content);
}
