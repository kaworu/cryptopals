/*
 * nope.c
 *
 * A NULL block cipher, used for testing block cipher mode of operation.
 */
#include "nope.h"


struct bytes *
nope_crypt(const struct bytes *input, const struct bytes *key)
{
	(void)key; /* shut up -Wunused-parameter */

	if (input == NULL || input->len != nope_blocksize())
		return (NULL);

	return (bytes_dup(input));
}


size_t
nope_keylength(void)
{
	return (0);
}


size_t
nope_blocksize(void)
{
	return (16);
}
