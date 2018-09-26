#ifndef DH_H
#define DH_H
/*
 * dh.h
 *
 * Diffie–Hellman–Merkle key exchange stuff.
 */
#include "bytes.h"
#include "bignum.h"


/*
 * An opaque structure used to represent the interface of a DH client.
 *
 * This struct uses an opaque pointer for data members and function members for
 * implementation so that it can be used for a MITM implementation as well.
 */
struct dh {
	/* implementation defined data */
	void	*opaque;

	/*
	 * Initiate a DH exchange between an "initiator" (self) and a "receiver"
	 * (bob). Once this function return successfully, self and bob have
	 * setup a shared AES 128 key derived from the DH exchange shared secret
	 * number.
	 *
	 * p is the public (prime) modulus, g is the public (prime) base.
	 *
	 * Returns 0 on success, -1 on error.
	 */
	int	(*exchange)(struct dh *self, struct dh *bob,
			    const struct bignum *p, const struct bignum *g);

	/*
	 * Receive a DH exchange initiated by alice. Here self (bob) will
	 * generate its own couple of private/public numbers and derive the
	 * shared secret.
	 *
	 * Returns bob's public number allowing the caller (alice) to compute
	 * the shared secret on success, NULL on failure.
	 */
	struct bignum	*(*receive)(struct dh *self, const struct bignum *p,
			    const struct bignum *g, const struct bignum *A);

	/*
	 * Returns a copy of the shared secret key.
	 *
	 * NOTE: This function is used by the test suites for debugging, it's
	 * obviously a bad idea to leak the secret shared key.
	 *
	 * Returns a pointer to a newly allocated bytes struct that should
	 * passed to bytes_free(). Returns NULL if the given pointer is NULL, or
	 * malloc(3) failed.
	 */
	struct bytes	*(*key)(const struct dh *self);

	/*
	 * Free the resource associated with the given dh struct.
	 *
	 * If not NULL, the data will be zero'd before freed.
	 */
	void	(*free)(struct dh *self);
};


/*
 * Create a new DH client.
 *
 * Returns a pointer to a newly allocated dh struct that should passed to its
 * free function member, or NULL if malloc(3) failed.
 */
struct dh	*dh_new(void);

/*
 * Derive an AES 128 key from a bignum secret number.
 *
 * The secret number is first hashed using SHA-1. Then, the first 16 bytes of
 * the hash are used as the AES 128 key.
 *
 * Returns a bytes buffer that can be used as an AES 128 key on success, or NULL
 * on failure.
 */
struct bytes	*dh_secret_to_aes128_key(const struct bignum *s);

#endif /* ndef DH_H */
