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

#endif /* ndef MAC_H */
