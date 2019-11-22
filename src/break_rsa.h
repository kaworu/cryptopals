#ifndef SRC_BREAK_RSA_H
#define SRC_BREAK_RSA_H
/*
 * break_rsa.h
 *
 * RSA e=3 broadcast attack stuff.
 */
#include "bytes.h"
#include "rsa.h"


/*
 * Decrypt a message given three ciphertexts c0, c1, c2 resulting from the same
 * message RSA e=3 encrypted thrice under three different keys k0, respectively
 * k1, k2.
 *
 * Returns the computed plaintext or NULL on error.
 */
struct bytes	*rsa_e3_broadcast_attack(
		    const struct bytes *c0, const struct rsa_pubkey *k0,
		    const struct bytes *c1, const struct rsa_pubkey *k1,
		    const struct bytes *c2, const struct rsa_pubkey *k2);

#endif /* ndef SRC_BREAK_RSA_H */
