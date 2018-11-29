/*
 * break_srp.c
 *
 * Secure Remote Password (SRP) parameters injection stuff.
 */
#include <stdlib.h>

#include "compat.h"
#include "sha256.h"
#include "mac.h"
#include "break_srp.h"


/* client method members implementations */
static int	srp_spoof_client_authenticate(struct srp_client *client,
		    struct srp_server *server);
static void	srp_spoof_client_free(struct srp_client *client);


struct srp_client *
srp_spoof_client_new(enum srp_spoof_client_type type, const struct bytes *I)
{
	struct srp_client *client = NULL;
	int success = 0;

	/* sanity checks */
	if (I == NULL)
		goto cleanup;

	client = calloc(1, sizeof(struct srp_client));
	if (client == NULL)
		goto cleanup;

	client->opaque = calloc(1, sizeof(struct srp_spoof_client_opaque));
	if (client->opaque == NULL)
		goto cleanup;
	struct srp_spoof_client_opaque *clientinfo = client->opaque;

	clientinfo->type = type;
	clientinfo->I = bytes_dup(I);
	if (clientinfo->I == NULL)
		goto cleanup;

	client->authenticate = srp_spoof_client_authenticate;
	client->free = srp_spoof_client_free;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		srp_spoof_client_free(client);
		client = NULL;
	}
	return (client);
}


static int
srp_spoof_client_authenticate(struct srp_client *client,
		    struct srp_server *server)
{
	struct bignum *A = NULL, *B = NULL, *S = NULL;
	struct bytes *salt = NULL, *Sb = NULL, *K = NULL, *token = NULL;
	int success = 0;

	/* sanity checks */
	if (client == NULL || client->opaque == NULL || server == NULL)
		goto cleanup;

	const struct srp_spoof_client_opaque *clientinfo = client->opaque;

	/* Pick A depending on our attack type */
	switch (clientinfo->type) {
	case SRP_SPOOF_CLIENT_0_AS_A:
		A = bignum_zero();
		S = bignum_zero();
		break;
	case SRP_SPOOF_CLIENT_N_AS_A:
		if (srp_parameters(&A, NULL, NULL) != 0)
			goto cleanup;
		S = bignum_zero();
		break;
	}
	if (A == NULL || S == NULL)
		goto cleanup;

	if (server->start(server, clientinfo->I, A, &salt, &B) != 0)
		goto cleanup;

	/* Generate K = SHA256(S) */
	Sb = bignum_to_bytes_be(S);
	K  = sha256_hash(Sb);
	if (K == NULL)
		goto cleanup;

	/* Generate and send the token to the server */
	token = hmac_sha256(K, salt);
	if (server->finalize(server, token) != 0)
		goto cleanup;

	success = 1;

	/* save the shared key */
	bytes_free(client->key);
	client->key = K;
	K = NULL;

	/* FALLTHROUGH */
cleanup:
	bytes_free(token);
	bytes_free(K);
	bytes_free(Sb);
	bignum_free(S);
	bytes_free(salt);
	bignum_free(B);
	bignum_free(A);
	return (success ? 0 : -1);
}


static void
srp_spoof_client_free(struct srp_client *client)
{
	if (client == NULL)
		return;

	if (client->opaque != NULL) {
		struct srp_spoof_client_opaque *clientinfo = client->opaque;
		bytes_free(clientinfo->I);
		freezero(clientinfo, sizeof(struct srp_spoof_client_opaque));
	}
	bytes_free(client->key);
	freezero(client, sizeof(struct srp_client));
}
