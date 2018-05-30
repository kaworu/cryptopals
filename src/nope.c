/*
 * nope.c
 *
 * A NULL block cipher, used for testing block cipher mode of operation.
 */
#include "nope.h"


size_t
nope_keylength(void)
{
	return (1);
}


size_t
nope_expkeylength(void)
{
	return (2);
}


size_t
nope_blocksize(void)
{
	return (16);
}


struct bytes *
nope_expand_key(const struct bytes *key)
{
	struct bytes *expanded = NULL;
	int success = 0;

	/* sanity checks */
	if (key == NULL || key->len != nope_keylength())
		goto cleanup;

	expanded = bytes_repeated(key->len + 1, 0xbb);
	if (expanded == NULL)
		goto cleanup;

	if (bytes_put(expanded, 0, key) != 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		bytes_free(expanded);
		expanded = NULL;
	}
	return (expanded);
}


struct bytes *
nope_crypt(const struct bytes *input, const struct bytes *expkey)
{
	/* sanity checks */
	if (input == NULL || input->len != nope_blocksize())
		return (NULL);
	if (expkey == NULL || expkey->len != nope_expkeylength())
		return (NULL);

	return (bytes_dup(input));
}
