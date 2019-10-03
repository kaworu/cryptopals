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
static int		 dh_mitm_negociate(struct dh *self, const struct mpi *p,
		    const struct mpi *g, struct mpi **np_p, struct mpi **ng_p);
static struct mpi	*dh_mitm_receive(struct dh *self, const struct mpi *p,
		    const struct mpi *g, const struct mpi *A);
static struct bytes	*dh_mitm_echo(const struct dh *self,
		    const struct bytes *iv_ct);
static void		 dh_mitm_free(struct dh *self);


struct dh *
dh_mitm_new(enum dh_mitm_type type, struct dh *bob)
{
	struct dh_mitm_opaque *dhinfo = NULL;
	struct dh *client = NULL;

	/* sanity checks */
	if (bob == NULL)
		return (NULL);

	client = calloc(1, sizeof(struct dh));
	if (client == NULL)
		return (NULL);

	dhinfo = calloc(1, sizeof(struct dh_mitm_opaque));
	if (dhinfo == NULL) {
		freezero(client, sizeof(struct dh));
		return (NULL);
	}

	client->negociate = dh_mitm_negociate;
	client->receive   = dh_mitm_receive;
	client->echo      = dh_mitm_echo;
	client->free      = dh_mitm_free;
	client->opaque    = dhinfo;
	dhinfo->type = type;
	dhinfo->bob  = bob;

	return (client);
}


static int
dh_mitm_negociate(struct dh *self, const struct mpi *p, const struct mpi *g,
		    struct mpi **np_p, struct mpi **ng_p)
{
	struct dh_mitm_opaque *dhinfo = NULL;
	struct mpi *spoofed_g = NULL, *np = NULL, *ng = NULL;
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

	dhinfo = self->opaque;
	struct dh *bob = dhinfo->bob;
	switch (dhinfo->type) {
	case DH_MITM_P_AS_A:
		/* simply pass the negociation parameters to bob, this attack is
		   about the public numbers at the exchange step. */
		spoofed_g = mpi_dup(g);
		break;
	case DH_MITM_1_AS_G:
		/* g = 1 */
		spoofed_g = mpi_one();
		break;
	case DH_MITM_P_AS_G:
		/* g = p */
		spoofed_g = mpi_dup(p);
		break;
	case DH_MITM_P_MINUS_1_AS_G:
		/* g = p - 1 */
		spoofed_g = mpi_subn(p, 1);
		break;
	}

	/* negociate our spoofed parameters with bob */
	if (bob->negociate(bob, p, spoofed_g, &np, &ng) != 0)
		goto cleanup;
	if (np == NULL || ng == NULL)
		goto cleanup;

	/* check that bob accepted our g value */
	if (mpi_cmp(spoofed_g, ng) != 0)
		goto cleanup;

	success = 1;

	/* set the negociated parameters for alice */
	*np_p = np;
	np = NULL;
	*ng_p = ng;
	ng = NULL;

	/* FALLTHROUGH */
cleanup:
	mpi_free(spoofed_g);
	mpi_free(ng);
	mpi_free(np);
	return (success ? 0 : -1);
}


static struct mpi *
dh_mitm_receive(struct dh *self, const struct mpi *p, const struct mpi *g,
		    const struct mpi *A)
{
	struct dh_mitm_opaque *dhinfo = NULL;
	struct mpi *p_minus_one = NULL, *s = NULL, *B = NULL;
	int success = 0;

	/* sanity checks */
	if (self == NULL || p == NULL || g == NULL || A == NULL)
		goto cleanup;
	if (self->opaque == NULL)
		goto cleanup;

	dhinfo = self->opaque;
	struct dh *bob = dhinfo->bob;
	switch (dhinfo->type) {
	case DH_MITM_P_AS_A:
		/* This is the attack, send (p, g, p) to Bob */
		B = bob->receive(bob, p, g, p);
		if (B == NULL)
			goto cleanup;
		mpi_free(B);
		/* we'll send back p to alice as bob's public number */
		B = mpi_dup(p);
		if (B == NULL)
			goto cleanup;
		/* The private shared number is zero */
		s = mpi_zero();
		break;
	case DH_MITM_1_AS_G:
		/* ensure that g = 1 */
		if (mpi_test_one(g) != 0)
			goto cleanup;
		/* forward the parameters to bob */
		B = bob->receive(bob, p, g, A);
		if (B == NULL)
			goto cleanup;
		/* The private shared number is one */
		s = mpi_one();
		break;
	case DH_MITM_P_AS_G:
		/* ensure that g = p */
		if (mpi_cmp(g, p) != 0)
			goto cleanup;
		/* forward the parameters to bob */
		B = bob->receive(bob, p, g, A);
		if (B == NULL)
			goto cleanup;
		/* The private shared number is zero */
		s = mpi_zero();
		break;
	case DH_MITM_P_MINUS_1_AS_G:
		p_minus_one = mpi_subn(p, 1);
		/* ensure that g = p - 1 */
		if (mpi_cmp(g, p_minus_one) != 0)
			goto cleanup;
		/* forward the parameters to bob */
		B = bob->receive(bob, p, g, A);
		if (B == NULL)
			goto cleanup;
		/* The private shared number is either p - 1 or 1 */
		if (mpi_cmp(A, p_minus_one) == 0 &&
			    mpi_cmp(B, p_minus_one) == 0) {
			s = mpi_dup(p_minus_one);
		} else {
			s = mpi_one();
		}
		break;
	}

	self->key = dh_secret_to_aes128_key(s);
	if (self->key == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	mpi_free(s);
	mpi_free(p_minus_one);
	return (success ? B : NULL);
}


static struct bytes *
dh_mitm_echo(const struct dh *self, const struct bytes *alice_iv_ct)
{
	struct dh_mitm_opaque *dhinfo = NULL;
	struct bytes *alice_iv = NULL, *alice_ct = NULL;
	struct bytes *msg = NULL, *bob_iv_ct = NULL;
	int success = 0;

	/* sanity checks */
	if (self == NULL || alice_iv_ct == NULL)
		goto cleanup;
	if (self->opaque == NULL)
		goto cleanup;

	dhinfo = self->opaque;
	struct dh *bob = dhinfo->bob;
	const size_t ivlen = aes_128_blocksize();

	/* split and decrypt the message */
	alice_iv  = bytes_slice(alice_iv_ct, 0, ivlen);
	alice_ct  = bytes_slice(alice_iv_ct, ivlen, alice_iv_ct->len - ivlen);
	msg = aes_128_cbc_decrypt(alice_ct, self->key, alice_iv);
	if (msg == NULL)
		goto cleanup;

	/* grow the messages array so that we can append the current one */
	struct bytes **messages = recallocarray(dhinfo->messages, dhinfo->count,
			dhinfo->count + 1, sizeof(*dhinfo->messages));
	if (messages == NULL)
		goto cleanup;
	dhinfo->messages = messages;
	messages = NULL;
	dhinfo->messages[dhinfo->count] = msg;
	msg = NULL;
	dhinfo->count += 1;

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
	struct dh_mitm_opaque *dhinfo = self->opaque;
	if (dhinfo != NULL) {
		struct dh *bob = dhinfo->bob;
		if (bob != NULL)
			bob->free(bob);
		for (size_t i = 0; i < dhinfo->count; i++)
			bytes_free(dhinfo->messages[i]);
		freezero(dhinfo->messages,
			    dhinfo->count * sizeof(struct bytes *));
	}
	freezero(dhinfo, sizeof(struct dh_mitm_opaque));
	freezero(self, sizeof(struct dh));
}
