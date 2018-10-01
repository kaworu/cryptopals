#ifndef BREAK_DH_H
#define BREAK_DH_H
/*
 * break_dh.h
 *
 * Diffie–Hellman–Merkle key exchange Man-In-The-Middle stuff.
 */
#include "dh.h"


/*
 * Types of MITM attack.
 */
enum dh_mitm_type {
	/*
	 * Pass the public parameter p as A (alice's public number) to bob and
	 * to alice as B (bob's public number). This effectively set the private
	 * shared secret number to zero.
	 *
	 * This is the attack described in Set 5 / Challenge 34.
	 */
	DH_MITM_P_AS_A,

	/*
	 * TODO
	 *
	 * This is the first attack described in Set 5 / Challenge 35.
	 */
	DH_MITM_1_AS_G,

	/*
	 * TODO
	 *
	 * This is the second attack described in Set 5 / Challenge 35.
	 */
	DH_MITM_P_AS_G,

	/*
	 * TODO
	 *
	 * This is the third attack described in Set 5 / Challenge 35.
	 */
	DH_MITM_P_MINUS_1_AS_G,
};

/*
 * Used as opaque member for the struct dh returned by dh_mitm_new().
 *
 * Hold an owned pointer to bob to relay alice's messages, and the decrypted
 * messages sent by alice.
 */
struct dh_mitm_opaque {
	enum dh_mitm_type type;
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
struct dh	*dh_mitm_new(enum dh_mitm_type type, struct dh *bob);

#endif /* ndef BREAK_DH_H */
