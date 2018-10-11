/*
 * break_dh.c
 *
 * Diffie–Hellman–Merkle key exchange Man-In-The-Middle stuff.
 */
#include <stdlib.h>

#include "compat.h"
#include "aes.h"
#include "cbc.h"
#include "break_dh.h"


/* implementations for the struct dh function members */
static int		 dh_mitm_negociate(struct dh *self,
		    const struct bignum *p, const struct bignum *g,
		    struct bignum **np_p, struct bignum **ng_p);
static struct bignum	*dh_mitm_receive(struct dh *self, const struct bignum *p,
		    const struct bignum *g, const struct bignum *A);
static struct bytes	*dh_mitm_echo(const struct dh *self,
		    const struct bytes *iv_ct);
static void		 dh_mitm_free(struct dh *self);


struct dh *
dh_mitm_new(enum dh_mitm_type type, struct dh *bob)
{
	struct dh_mitm_opaque *ad = NULL;
	struct dh *client = NULL;

	/* sanity checks */
	if (bob == NULL)
		return (NULL);

	client = calloc(1, sizeof(struct dh));
	if (client == NULL)
		return (NULL);

	ad = calloc(1, sizeof(struct dh_mitm_opaque));
	if (ad == NULL) {
		freezero(client, sizeof(struct dh));
		return (NULL);
	}

	client->negociate = dh_mitm_negociate;
	client->receive   = dh_mitm_receive;
	client->echo      = dh_mitm_echo;
	client->free      = dh_mitm_free;
	client->opaque    = ad;
	ad->type = type;
	ad->bob  = bob;

	return (client);
}


static int
dh_mitm_negociate(struct dh *self,
		    const struct bignum *p, const struct bignum *g,
		    struct bignum **np_p, struct bignum **ng_p)
{
	struct dh_mitm_opaque *ad = NULL;
	struct bignum *spoofed_g = NULL, *np = NULL, *ng = NULL;
	int success = 0;

	/* sanity checks */
	if (self == NULL)
		goto cleanup;
	if (p == NULL || g == NULL)
		goto cleanup;
	if (np_p == NULL || ng_p == NULL)
		goto cleanup;
	if (self->opaque == NULL)
		goto cleanup;

	ad = self->opaque;
	struct dh *bob = ad->bob;
	switch (ad->type) {
	case DH_MITM_P_AS_A:
		/* simply pass the negociation parameters to bob, this attack is
		   about the public numbers at the exchange step. */
		spoofed_g = bignum_dup(g);
		break;
	case DH_MITM_1_AS_G:
		/* g = 1 */
		spoofed_g = bignum_one();
		break;
	case DH_MITM_P_AS_G:
		/* g = p */
		spoofed_g = bignum_dup(p);
		break;
	case DH_MITM_P_MINUS_1_AS_G:
		/* g = p - 1 */
		spoofed_g = bignum_sub_one(p);
		break;
	}

	/* negociate our spoofed parameters with bob */
	if (bob->negociate(bob, p, spoofed_g, &np, &ng) != 0)
		goto cleanup;
	if (np == NULL || ng == NULL)
		goto cleanup;

	/* check that bob accepted our g value */
	if (bignum_cmp(spoofed_g, ng) != 0)
		goto cleanup;

	success = 1;

	/* set the negociated parameters for alice */
	*np_p = np;
	np = NULL;
	*ng_p = ng;
	ng = NULL;

	/* FALLTHROUGH */
cleanup:
	bignum_free(spoofed_g);
	bignum_free(ng);
	bignum_free(np);
	return (success ? 0 : -1);
}


static struct bignum *
dh_mitm_receive(struct dh *self, const struct bignum *p, const struct bignum *g,
		    const struct bignum *A)
{
	struct dh_mitm_opaque *ad = NULL;
	struct bignum *p_minus_one = NULL, *s = NULL, *B = NULL;
	int success = 0;

	/* sanity checks */
	if (self == NULL || p == NULL || g == NULL || A == NULL)
		goto cleanup;
	if (self->opaque == NULL)
		goto cleanup;

	ad = self->opaque;
	struct dh *bob = ad->bob;
	switch (ad->type) {
	case DH_MITM_P_AS_A:
		/* This is the attack, send (p, g, p) to Bob */
		B = bob->receive(bob, p, g, p);
		if (B == NULL)
			goto cleanup;
		bignum_free(B);
		/* we'll send back p to alice as bob's public number */
		B = bignum_dup(p);
		if (B == NULL)
			goto cleanup;
		/* The private shared number is zero */
		s = bignum_zero();
		break;
	case DH_MITM_1_AS_G:
		/* ensure that g = 1 */
		if (bignum_is_one(g) != 0)
			goto cleanup;
		/* forward the parameters to bob */
		B = bob->receive(bob, p, g, A);
		if (B == NULL)
			goto cleanup;
		/* The private shared number is one */
		s = bignum_one();
		break;
	case DH_MITM_P_AS_G:
		/* ensure that g = p */
		if (bignum_cmp(g, p) != 0)
			goto cleanup;
		/* forward the parameters to bob */
		B = bob->receive(bob, p, g, A);
		if (B == NULL)
			goto cleanup;
		/* The private shared number is zero */
		s = bignum_zero();
		break;
	case DH_MITM_P_MINUS_1_AS_G:
		p_minus_one = bignum_sub_one(p);
		/* ensure that g = p - 1 */
		if (bignum_cmp(g, p_minus_one) != 0)
			goto cleanup;
		/* forward the parameters to bob */
		B = bob->receive(bob, p, g, A);
		if (B == NULL)
			goto cleanup;
		/* The private shared number is either p - 1 or 1 */
		if (bignum_cmp(A, p_minus_one) == 0 &&
			    bignum_cmp(B, p_minus_one) == 0) {
			s = bignum_dup(p_minus_one);
		} else {
			s = bignum_one();
		}
		break;
	}

	self->key = dh_secret_to_aes128_key(s);
	if (self->key == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bignum_free(s);
	bignum_free(p_minus_one);
	return (success ? B : NULL);
}


static struct bytes *
dh_mitm_echo(const struct dh *self, const struct bytes *alice_iv_ct)
{
	struct dh_mitm_opaque *ad = NULL;
	struct bytes *alice_iv = NULL, *alice_ct = NULL;
	struct bytes *msg = NULL, *bob_iv_ct = NULL;
	int success = 0;

	/* sanity checks */
	if (self == NULL || alice_iv_ct == NULL)
		goto cleanup;
	if (self->opaque == NULL)
		goto cleanup;

	ad = self->opaque;
	struct dh *bob = ad->bob;
	const size_t ivlen = aes_128_blocksize();

	/* split and decrypt the message */
	alice_iv  = bytes_slice(alice_iv_ct, 0, ivlen);
	alice_ct  = bytes_slice(alice_iv_ct, ivlen, alice_iv_ct->len - ivlen);
	msg = aes_128_cbc_decrypt(alice_ct, self->key, alice_iv);
	if (msg == NULL)
		goto cleanup;

	/* grow the messages array so that we can append the current one */
	struct bytes **messages = recallocarray(ad->messages, ad->count,
			ad->count + 1, sizeof(*ad->messages));
	if (messages == NULL)
		goto cleanup;
	ad->messages = messages;
	messages = NULL;
	ad->messages[ad->count] = msg;
	msg = NULL;
	ad->count += 1;

	/* forward the echo message to Bob */
	bob_iv_ct = bob->echo(bob, alice_iv_ct);
	if (bob_iv_ct == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(msg);
	bytes_free(alice_ct);
	bytes_free(alice_iv);
	if (!success) {
		bytes_free(bob_iv_ct);
		bob_iv_ct = NULL;
	}
	return (bob_iv_ct);
}


static void
dh_mitm_free(struct dh *self)
{
	if (self == NULL)
		return;

	bytes_free(self->key);
	struct dh_mitm_opaque *ad = self->opaque;
	if (ad != NULL) {
		struct dh *bob = ad->bob;
		if (bob != NULL)
			bob->free(bob);
		for (size_t i = 0; i < ad->count; i++)
			bytes_free(ad->messages[i]);
		freezero(ad->messages, ad->count * sizeof(struct bytes *));
	}
	freezero(ad, sizeof(struct dh_mitm_opaque));
	freezero(self, sizeof(struct dh));
}
