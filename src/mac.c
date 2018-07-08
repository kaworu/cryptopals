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
 * Generic HMAC construction function.
 */
static struct bytes	*hmac(hash_func_t *H, size_t B, size_t L,
		    const struct bytes *key, const struct bytes *msg);

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


struct bytes *
hmac_sha1(const struct bytes *key, const struct bytes *msg)
{
	const size_t blocksize  = sha1_blocksize();
	const size_t hashlength = sha1_hashlength();
	return (hmac(&sha1_hash, blocksize, hashlength, key, msg));
}


struct bytes *
hmac_md4(const struct bytes *key, const struct bytes *msg)
{
	const size_t blocksize  = md4_blocksize();
	const size_t hashlength = md4_hashlength();
	return (hmac(&md4_hash, blocksize, hashlength, key, msg));
}


static struct bytes *
hmac(hash_func_t *H, size_t B, size_t L,
		    const struct bytes *key, const struct bytes *msg)
{
	struct bytes *tk = NULL;
	struct bytes *k_ipad = NULL, *k_opad = NULL;
	struct bytes *in = NULL, *hin = NULL, *out = NULL;
	struct bytes *mac = NULL;
	int success = 0;

	/* sanity checks */
	if (H == NULL || key == NULL || msg == NULL)
		goto cleanup;

	if (key->len > B) {
		/*
		 * From § 2:
		 * Applications that use keys longer than B bytes will first
		 * hash the key using H and then use the resultant L byte string
		 * as the actual key to HMAC.
		 *
		 * NOTE: see https://www.rfc-editor.org/errata/eid4809
		 */
		struct bytes *hkey = H(key);
		tk = bytes_slice(hkey, 0, L);
		bytes_free(hkey);
	} else {
		tk = bytes_dup(key);
	}
	if (tk == NULL)
		goto cleanup;

	/*
	 * Build ipad and opad; the key followed by zeros, XOR'ed with 0x36,
	 * respectively 0x5c.
	 */
	k_ipad = bytes_zeroed(B);
	if (k_ipad == NULL)
		goto cleanup;
	if (bytes_put(k_ipad, 0, tk) != 0)
		goto cleanup;
	k_opad = bytes_dup(k_ipad);
	if (k_opad == NULL)
		goto cleanup;
	for (size_t i = 0; i < B; i++) {
		k_ipad->data[i] ^= 0x36;
		k_opad->data[i] ^= 0x5c;
	}

	/* H(K XOR opad, H(K XOR ipad, text)) */

	const struct bytes *iparts[] = { k_ipad, msg };
	in = bytes_joined_const(iparts, sizeof(iparts) / sizeof(*iparts));
	hin = H(in);
	const struct bytes *oparts[] = { k_opad, hin };
	out = bytes_joined_const(oparts, sizeof(oparts) / sizeof(*oparts));
	mac = H(out);
	if (mac == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(out);
	bytes_free(hin);
	bytes_free(in);
	bytes_free(k_opad);
	bytes_free(k_ipad);
	bytes_free(tk);
	if (!success) {
		bytes_free(mac);
		mac = NULL;
	}
	return (mac);
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
