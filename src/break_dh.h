#ifndef BREAK_DH_H
#define BREAK_DH_H
/*
 * break_dh.h
 *
 * Diffie–Hellman–Merkle key exchange Man-In-The-Middle stuff.
 */
#include "dh.h"


/*
 * Used as opaque member for the struct dh returned by dh_mitm_new().
 *
 * Hold an owned pointer to Bob to relay Alice's messages, and the decrypted
 * messages sent by Alice.
 */
struct dh_mitm_opaque {
	struct dh *bob;
	size_t count;
	struct bytes **messages;
};


/*
 * Create a new DH MITM client.
 *
 * On success, the returned client take ownership of the given pointer.
 *
 * Returns a pointer to a newly allocated dh struct that should passed to its
 * free function member, NULL if the given pointer is NULL or malloc(3) failed.
 */
struct dh	*dh_mitm_new(struct dh *bob);

#endif /* ndef BREAK_DH_H */
