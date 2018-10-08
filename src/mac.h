#ifndef MAC_H
#define MAC_H
/*
 * mac.h
 *
 * Message Authentication Code stuff for cryptopals.com challenges.
 */
#include "bytes.h"


/*
 * Authenticate a message using a SHA-1 keyed MAC as described in
 * Set 4 / Challenge 28.
 *
 * Use a secret-prefix MAC: SHA1(key || message).
 *
 * Returns the resulting MAC, or NULL on error.
 */
struct bytes	*sha1_mac_keyed_prefix(const struct bytes *key,
		    const struct bytes *msg);

/*
 * Verify a message using a SHA-1 keyed MAC as described in
 * Set 4 / Challenge 28.
 *
 * Use a secret-prefix MAC: SHA1(key || message).
 *
 * Returns 0 if the MAC is successfully verified, 1 if the MAC fails
 * verification, -1 on error.
 */
int	sha1_mac_keyed_prefix_verify(const struct bytes *key,
		    const struct bytes *msg, const struct bytes *mac);

/*
 * Authenticate a message using a MD4 keyed MAC as described in
 * Set 4 / Challenge 30.
 *
 * Use a secret-prefix MAC: MD4(key || message).
 *
 * Returns the resulting MAC, or NULL on error.
 */
struct bytes	*md4_mac_keyed_prefix(const struct bytes *key,
		    const struct bytes *msg);

/*
 * Verify a message using a MD4 keyed MAC as described in
 * Set 4 / Challenge 30.
 *
 * Use a secret-prefix MAC: MD4(key || message).
 *
 * Returns 0 if the MAC is successfully verified, 1 if the MAC fails
 * verification, -1 on error.
 */
int	md4_mac_keyed_prefix_verify(const struct bytes *key,
		    const struct bytes *msg, const struct bytes *mac);

/*
 * Returns the HMAC-SHA1 MAC of the given message under the provided key, or
 * NULL on error (either argument is NULL or malloc failed).
 */
struct bytes	*hmac_sha1(const struct bytes *key, const struct bytes *msg);

/*
 * Returns the HMAC-MD4 MAC of the given message under the provided key, or NULL
 * on error (either argument is NULL or malloc failed).
 */
struct bytes	*hmac_md4(const struct bytes *key, const struct bytes *msg);

/*
 * Returns the HMAC-SHA256 MAC of the given message under the provided key, or
 * NULL on error (either argument is NULL or malloc failed).
 */
struct bytes	*hmac_sha256(const struct bytes *key, const struct bytes *msg);

#endif /* ndef MAC_H */
