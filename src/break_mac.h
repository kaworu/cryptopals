#ifndef BREAK_MAC_H
#define BREAK_MAC_H
/*
 * break_mac.h
 *
 * MAC analysis stuff for cryptopals.com challenges.
 */
#include "bytes.h"


/*
 * Break SHA-1 Keyed MAC using length extension as described in
 * Set 4 / Challenge 29.
 *
 * Returns 0 on success, -1 on error or failure to extend.
 *
 * When 0 is returned and msg_p and mac_p are not NULL, they are set to the
 * extended message and its MAC respectively. Both are expected to be passed to
 * bytes_free(3) by the caller.
 */
int	extend_sha1_mac_keyed_prefix(const void *key,
		    const struct bytes *msg, const struct bytes *mac,
		    struct bytes **msg_p, struct bytes **mac_p);

/*
 * Break MD4 Keyed MAC using length extension as described in
 * Set 4 / Challenge 29 & 30.
 *
 * Returns 0 on success, -1 on error or failure to extend.
 *
 * When 0 is returned and msg_p and mac_p are not NULL, they are set to the
 * extended message and its MAC respectively. Both are expected to be passed to
 * bytes_free(3) by the caller.
 */
int	extend_md4_mac_keyed_prefix(const void *key,
		    const struct bytes *msg, const struct bytes *mac,
		    struct bytes **msg_p, struct bytes **mac_p);

/*
 * Break a server verifying HMAC-SHA1 with an artificial timing leak as
 * described in Set 4 / Challenge 31 & 32.
 *
 * the fmt argument is the query having exactly one %s replacement pattern that
 * will be replaced by the MAC. Note: this is highly insecure and no escape is
 * performed.
 *
 * Returns the hacked MAC on success, NULL on failure.
 */
struct bytes	*break_timing_leaking_server(const char *hostname,
		    const char *port, const char *fmt, size_t maclen);

#endif /* ndef BREAK_MAC_H */
