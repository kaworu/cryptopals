/*
 * dh.c
 *
 * Diffie–Hellman–Merkle key exchange stuff.
 */
#include <stdlib.h>

#include "compat.h"
#include "sha1.h"
#include "aes.h"
#include "cbc.h"
#include "dh.h"


/* implementations for the struct dh function members */
static int		 dh_exchange(struct dh *self, struct dh *bob,
		    const struct bignum *p, const struct bignum *g);
static int		 dh_negociate(struct dh *self,
		    const struct bignum *p, const struct bignum *g,
		    struct bignum **np_p, struct bignum **ng_p);
static struct bignum	*dh_receive(struct dh *self, const struct bignum *p,
		    const struct bignum *g, const struct bignum *A);
static int		 dh_challenge(const struct dh *self,
		    const struct dh *to, const struct bytes *msg);
static struct bytes	*dh_echo(const struct dh *self,
		    const struct bytes *iv_ct);
static void		 dh_free(struct dh *self);


struct dh *
dh_new(void)
{
	struct dh *client = NULL;

	client = calloc(1, sizeof(struct dh));
	if (client == NULL)
		return (NULL);

	client->exchange  = dh_exchange;
	client->negociate = dh_negociate;
	client->receive   = dh_receive;
	client->challenge = dh_challenge;
	client->echo      = dh_echo;
	client->free      = dh_free;

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
	struct bignum *np = NULL, *ng = NULL;
	struct bignum *a = NULL, *A = NULL, *B = NULL, *s = NULL;
	int success = 0;

	/* sanity checks */
	if (self == NULL || bob == NULL)
		goto cleanup;
	if (p == NULL || g == NULL)
		goto cleanup;

	/* negociate the public parameters p and g */
	if (bob->negociate(bob, p, g, &np, &ng) != 0)
		goto cleanup;

	/*
	 * np and ng are now the negociated parameters, no additional checks.
	 */

	/* generate Alice's private number a */
	a = bignum_rand(np);
	/* compute Alice's public number A */
	A = bignum_modexp(ng, a, np);
	/* send the DH parameters to Bob, he'll answer with his own public
	   number B */
	B = bob->receive(bob, np, ng, A);
	/* compute the shared secret using Bob's public number B and Alice's
	   private number a */
	s = bignum_modexp(B, a, np);

	/* reset associated data for Alice */
	bytes_free(self->key);
	/* Compute the shared key from the shared secret number s */
	self->key = dh_secret_to_aes128_key(s);
	if (self->key == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bignum_free(s);
	bignum_free(B);
	bignum_free(A);
	bignum_free(a);
	bignum_free(ng);
	bignum_free(np);
	return (success ? 0 : -1);
}


static int
dh_negociate(struct dh *self, const struct bignum *p, const struct bignum *g,
		    struct bignum **np_p, struct bignum **ng_p)
{
	struct bignum *np = NULL, *ng = NULL;
	int success = 0;

	/* sanity checks */
	if (self == NULL)
		goto cleanup;
	if (p == NULL || g == NULL)
		goto cleanup;
	if (np_p == NULL || ng_p == NULL)
		goto cleanup;

	/* no checks at all, just accept the proposed p and g */
	np = bignum_dup(p);
	ng = bignum_dup(g);
	if (np == NULL || ng == NULL)
		goto cleanup;

	success = 1;

	*np_p = np;
	np = NULL;
	*ng_p = ng;
	ng = NULL;

	/* FALLTHROUGH */
cleanup:
	bignum_free(ng);
	bignum_free(np);
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
	bytes_free(self->key);
	/* Compute the shared key from the shared secret number s */
	self->key = dh_secret_to_aes128_key(s);
	if (self->key == NULL)
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


static int
dh_challenge(const struct dh *self, const struct dh *to,
		    const struct bytes *msg)
{
	struct bytes *iv = NULL, *ct = NULL, *iv_ct = NULL;
	struct bytes *bob_iv_ct = NULL, *bob_iv = NULL, *bob_ct = NULL,
		     *bob_msg = NULL;
	int success = 0;

	/* sanity checks */
	if (self == NULL || to == NULL || msg == NULL)
		goto cleanup;

	const size_t ivlen = aes_128_blocksize();

	/* encrypt the message, and create a iv + ciphertext buffer to be sent
	   to Bob */
	iv = bytes_randomized(ivlen);
	ct = aes_128_cbc_encrypt(msg, self->key, iv);
	iv_ct = bytes_joined(2, iv, ct);

	/* send our iv + ciphertext buffer to bob and get its re-encrypted
	   version of the message */
	bob_iv_ct = to->echo(to, iv_ct);
	/* ensure that bob has used a different IV than we did */
	if (bob_iv_ct == NULL || bytes_timingsafe_bcmp(bob_iv_ct, iv_ct) == 0)
		goto cleanup;

	/* split and decrypt its version of the message */
	bob_iv  = bytes_slice(bob_iv_ct, 0, ivlen);
	bob_ct  = bytes_slice(bob_iv_ct, ivlen, bob_iv_ct->len - ivlen);
	bob_msg = aes_128_cbc_decrypt(bob_ct, self->key, bob_iv);

	/* if Bob's message is the same as our own then it's a success */
	if (bytes_timingsafe_bcmp(msg, bob_msg) != 0)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(bob_msg);
	bytes_free(bob_ct);
	bytes_free(bob_iv);
	bytes_free(bob_iv_ct);
	bytes_free(iv_ct);
	bytes_free(ct);
	bytes_free(iv);
	return (success ? 0 : -1);
}


static struct bytes *
dh_echo(const struct dh *self, const struct bytes *alice_iv_ct)
{
	struct bytes *alice_iv = NULL, *alice_ct = NULL;
	struct bytes *msg = NULL, *iv = NULL, *ct = NULL, *iv_ct = NULL;
	int success = 0;

	/* sanity checks */
	if (self == NULL || alice_iv_ct == NULL)
		goto cleanup;

	const size_t ivlen = aes_128_blocksize();

	/* decrypt alice's message */
	alice_iv = bytes_slice(alice_iv_ct, 0, ivlen);
	alice_ct = bytes_slice(alice_iv_ct, ivlen, alice_iv_ct->len - ivlen);
	msg = aes_128_cbc_decrypt(alice_ct, self->key, alice_iv);

	/* XXX: there is a very small (but non-zero) probability that we
	   generate the same IV as Alice's IV */
	iv = bytes_randomized(ivlen);
	/* (re)encrypt the message, and create a iv + ciphertext buffer to be
	   returned to Alice */
	ct = aes_128_cbc_encrypt(msg, self->key, iv);
	iv_ct = bytes_joined(2, iv, ct);
	if (iv_ct == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(ct);
	bytes_free(iv);
	bytes_free(msg);
	bytes_free(alice_ct);
	bytes_free(alice_iv);
	if (!success) {
		bytes_free(iv_ct);
		iv_ct = NULL;
	}
	return (iv_ct);
}


static void
dh_free(struct dh *self)
{
	if (self == NULL)
		return;

	bytes_free(self->key);
	freezero(self, sizeof(struct dh));
}
