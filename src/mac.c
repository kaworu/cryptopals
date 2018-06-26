/*
 * mac.c
 *
 * Message Authentication Code stuff for cryptopals.com challenges.
 */
#include "sha1.h"
#include "md4.h"
#include "mac.h"


/*
 * Function type to generate a hash.
 */
typedef struct bytes *(hash_func_t)(const struct bytes *msg);


/*
 * Generic secret-prefix MAC functions.
 */
static struct bytes	*mac_keyed_prefix(hash_func_t *hash,
		    const struct bytes *key, const struct bytes *msg);

static int		mac_keyed_prefix_verify(hash_func_t *hash,
		    const struct bytes *key, const struct bytes *msg,
		    const struct bytes *mac);



struct bytes *
sha1_mac_keyed_prefix(const struct bytes *key, const struct bytes *msg)
{
	return (mac_keyed_prefix(&sha1_hash, key, msg));
}


int
sha1_mac_keyed_prefix_verify(const struct bytes *key,
		    const struct bytes *msg, const struct bytes *mac)
{
	return (mac_keyed_prefix_verify(&sha1_hash, key, msg, mac));
}


struct bytes *
md4_mac_keyed_prefix(const struct bytes *key, const struct bytes *msg)
{
	return (mac_keyed_prefix(&md4_hash, key, msg));
}


int
md4_mac_keyed_prefix_verify(const struct bytes *key,
		    const struct bytes *msg, const struct bytes *mac)
{
	return (mac_keyed_prefix_verify(&md4_hash, key, msg, mac));
}


static struct bytes *
mac_keyed_prefix(hash_func_t *hash,
		    const struct bytes *key, const struct bytes *msg)
{
	struct bytes *prefixed = NULL, *mac = NULL;
	int success = 0;

	if (hash == NULL || key == NULL || msg == NULL)
		goto cleanup;

	const struct bytes *const parts[] = { key, msg };
	prefixed = bytes_joined_const(parts, sizeof(parts) / sizeof(*parts));
	if (prefixed == NULL)
		goto cleanup;

	mac = hash(prefixed);
	if (mac == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(prefixed);
	if (!success) {
		bytes_free(mac);
		mac = NULL;
	}
	return (mac);
}


static int
mac_keyed_prefix_verify(hash_func_t *hash,
		    const struct bytes *key, const struct bytes *msg,
		    const struct bytes *mac)
{
	struct bytes *computed_mac = NULL;
	int success = 0;
	int match = 0;

	if (hash == NULL || key == NULL || msg == NULL || mac == NULL)
		goto cleanup;

	computed_mac = mac_keyed_prefix(hash, key, msg);
	if (computed_mac == NULL)
		goto cleanup;

	if (bytes_timingsafe_bcmp(computed_mac, mac) == 0)
		match = 1;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(computed_mac);
	if (!success)
		return (-1);
	return (match ? 0 : 1);
}
