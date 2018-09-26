/*
 * dh.c
 *
 * Diffie–Hellman–Merkle key exchange stuff.
 */
#include <stdlib.h>

#include "compat.h"
#include "sha1.h"
#include "aes.h"
#include "dh.h"


/* implementations for the struct dh function members */
static int		 dh_exchange(struct dh *self, struct dh *bob, const
		    struct bignum *p, const struct bignum *g);
static struct bignum	*dh_receive(struct dh *self, const struct bignum *p,
		    const struct bignum *g, const struct bignum *A);
static struct bytes	*dh_key(const struct dh *self);
static void		 dh_free(struct dh *self);


struct dh *
dh_new(void)
{
	struct dh *client = NULL;

	client = malloc(sizeof(struct dh));
	if (client == NULL)
		return (NULL);

	client->opaque   = NULL; /* the shared key */
	client->exchange = dh_exchange;
	client->receive  = dh_receive;
	client->key      = dh_key;
	client->free     = dh_free;

	return (client);
}


struct bytes *
dh_secret_to_aes128_key(const struct bignum *s)
{
	struct bytes *sbytes = NULL, *shash = NULL, *key = NULL;
	int success = 0;

	if (s == NULL)
		goto cleanup;

	sbytes = bignum_to_bytes_be(s);
	shash = sha1_hash(sbytes);
	key = bytes_slice(shash, 0, aes_128_keylength());
	if (key == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(shash);
	bytes_free(sbytes);
	if (!success) {
		bytes_free(key);
		key = NULL;
	}
	return (key);
}


static int
dh_exchange(struct dh *self, struct dh *bob, const struct bignum *p,
		    const struct bignum *g)
{
	struct bignum *a = NULL, *A = NULL, *B = NULL, *s = NULL;
	int success = 0;

	/* sanity checks */
	if (self == NULL || bob == NULL)
		goto cleanup;
	if (p == NULL || g == NULL)
		goto cleanup;

	/* generate Alice's private number a */
	a = bignum_rand(p);
	/* compute Alice's public number A */
	A = bignum_modexp(g, a, p);
	/* send the DH parameters to Bob, he'll answer with his own public
	   number B */
	B = bob->receive(bob, p, g, A);
	/* compute the shared secret using Bob's public number B and Alice's
	   private number a */
	s = bignum_modexp(B, a, p);

	/* reset associated data for Alice */
	bytes_free(self->opaque);
	/* Compute the shared key from the shared secret number s */
	self->opaque = dh_secret_to_aes128_key(s);
	if (self->opaque == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bignum_free(s);
	bignum_free(B);
	bignum_free(A);
	bignum_free(a);
	return (success ? 0 : -1);
}


static struct bignum *
dh_receive(struct dh *self, const struct bignum *p, const struct bignum *g,
		    const struct bignum *A)
{
	struct bignum *b = NULL, *s = NULL, *B = NULL;
	int success = 0;

	/* sanity checks */
	if (self == NULL || p == NULL || g == NULL || A == NULL)
		goto cleanup;

	/* generate Bob's private number b */
	b = bignum_rand(p);
	/* compute the shared secret using Alice's public number A and Bob's
	   private number b */
	s = bignum_modexp(A, b, p);
	/* compute Bob's public number B to be sent back to Alice */
	B = bignum_modexp(g, b, p);
	if (B == NULL)
		goto cleanup;

	/* reset associated data for Bob */
	bytes_free(self->opaque);
	/* Compute the shared key from the shared secret number s */
	self->opaque = dh_secret_to_aes128_key(s);
	if (self->opaque == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bignum_free(s);
	bignum_free(b);
	if (!success) {
		bignum_free(B);
		B = NULL;
	}
	return (B);
}


static struct bytes *
dh_key(const struct dh *self)
{
	if (self == NULL)
		return (NULL);

	return (bytes_dup(self->opaque));
}


static void
dh_free(struct dh *self)
{
	if (self != NULL)
		bytes_free(self->opaque);
	freezero(self, sizeof(struct dh));
}
