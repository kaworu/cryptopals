/*
 * ssrp.c
 *
 * Simplified Secure Remote Password (SSRP) stuff for cryptopals.com challenges.
 */
#include <stdlib.h>

#include "compat.h"
#include "sha256.h"
#include "mac.h"
#include "srp.h"
#include "ssrp.h"


/* local struct ssrp_server method members implementations */
static int	ssrp_local_server_start(struct ssrp_server *server,
		    const struct bytes *I, const struct mpi *A,
		    struct bytes **salt_p, struct mpi **B_p, struct mpi **u_p);
static int	ssrp_local_server_finalize(struct ssrp_server *server,
		    const struct bytes *token);
static void	ssrp_local_server_free(struct ssrp_server *server);

/* struct ssrp_client method members implementations */
static int	ssrp_client_authenticate(struct ssrp_client *client,
		    struct ssrp_server *server);
static void	ssrp_client_free(struct ssrp_client *client);


struct ssrp_server *
ssrp_local_server_new(const struct bytes *I, const struct bytes *P)
{
	struct ssrp_server *server = NULL;
	int success = 0;

	/* sanity checks */
	if (I == NULL || P == NULL)
		goto cleanup;

	server = calloc(1, sizeof(struct ssrp_server));
	if (server == NULL)
		goto cleanup;

	server->opaque = calloc(1, sizeof(struct ssrp_local_server_opaque));
	if (server->opaque == NULL)
		goto cleanup;
	struct ssrp_local_server_opaque *srvinfo = server->opaque;

	srvinfo->I = bytes_dup(I);
	srvinfo->P = bytes_dup(P);
	if (srvinfo->I == NULL || srvinfo->P == NULL)
		goto cleanup;

	server->start    = ssrp_local_server_start;
	server->finalize = ssrp_local_server_finalize;
	server->free     = ssrp_local_server_free;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		ssrp_local_server_free(server);
		server = NULL;
	}
	return (server);
}


struct ssrp_client *
ssrp_client_new(const struct bytes *I, const struct bytes *P)
{
	struct ssrp_client *client = NULL;
	int success = 0;

	/* sanity checks */
	if (I == NULL || P == NULL)
		goto cleanup;

	client = calloc(1, sizeof(struct ssrp_client));
	if (client == NULL)
		goto cleanup;

	client->opaque = calloc(1, sizeof(struct ssrp_client_opaque));
	if (client->opaque == NULL)
		goto cleanup;
	struct ssrp_client_opaque *clientinfo = client->opaque;

	clientinfo->I = bytes_dup(I);
	clientinfo->P = bytes_dup(P);
	if (clientinfo->I == NULL || clientinfo->P == NULL)
		goto cleanup;

	client->authenticate = ssrp_client_authenticate;
	client->free = ssrp_client_free;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		ssrp_client_free(client);
		client = NULL;
	}
	return (client);
}


static int
ssrp_local_server_start(struct ssrp_server *server,
		    const struct bytes *I, const struct mpi *A,
		    struct bytes **salt_p, struct mpi **B_p, struct mpi **u_p)
{
	struct mpi *N = NULL, *g = NULL, *k = NULL;
	struct bytes *salt = NULL;
	struct mpi *x = NULL, *v = NULL;
	struct mpi *b = NULL, *B = NULL;
	struct mpi *u = NULL, *S = NULL;
	struct bytes *Sb = NULL, *K = NULL;
	struct bytes *token = NULL;
	int success = 0;

	/* sanity checks */
	if (server == NULL || server->opaque == NULL)
		goto cleanup;
	if (I == NULL || A == NULL)
		goto cleanup;
	if (salt_p == NULL || B_p == NULL || u_p == NULL)
		goto cleanup;

	struct ssrp_local_server_opaque *srvinfo = server->opaque;

	if (srp_parameters(&N, &g, &k) != 0)
		goto cleanup;

	/* ensure that I is the correct email */
	if (bytes_timingsafe_bcmp(srvinfo->I, I) != 0)
		goto cleanup;

	/* Generate salt as random integer */
	salt = bytes_randomized(SRP_SALT_BYTES);
	if (salt == NULL)
		goto cleanup;

	/* Generate string xH=SHA256(salt|password) */
	/* Convert xH to integer x somehow */
	x = srp_mpi_from_sha256_bytes(salt, srvinfo->P);
	if (x == NULL)
		goto cleanup;

	/* Generate v=g**x % N */
	v = mpi_mod_exp(g, x, N);
	if (v == NULL)
		goto cleanup;

	/* B=g**b % N */
	b = mpi_rand_range_from_one_to(N);
	B = mpi_mod_exp(g, b, N);
	if (B == NULL)
		goto cleanup;

	/* u = 128 bit random number */
	struct bytes *uH = bytes_randomized(16);
	u = mpi_from_bytes_be(uH);
	bytes_free(uH);
	if (u == NULL)
		goto cleanup;

	/* Generate S = (A * v**u) ** b % N */
	struct mpi *v_pow_u = mpi_mod_exp(v, u, N);
	struct mpi *A_times_v_pow_u = mpi_mod_mul(A, v_pow_u, N);
	S = mpi_mod_exp(A_times_v_pow_u, b, N);
	mpi_free(A_times_v_pow_u);
	mpi_free(v_pow_u);
	if (S == NULL)
		goto cleanup;

	/* Generate K = SHA256(S) */
	Sb = mpi_to_bytes_be(S);
	K  = sha256_hash(Sb);
	if (K == NULL)
		goto cleanup;

	/* Generate the HMAC-SHA256(K, salt) token */
	token = hmac_sha256(K, salt);
	if (token == NULL)
		goto cleanup;

	success = 1;

	/* save what we need for finalize() in the server */
	bytes_free(srvinfo->key);
	srvinfo->key = K;
	K = NULL;
	bytes_free(srvinfo->token);
	srvinfo->token = token;
	token = NULL;

	/* set "return" values for the caller */
	*salt_p = salt;
	salt = NULL;
	*B_p = B;
	B = NULL;
	*u_p = u;
	u = NULL;

	/* FALLTHROUGH */
cleanup:
	bytes_free(token);
	bytes_free(K);
	bytes_free(Sb);
	mpi_free(S);
	mpi_free(u);
	mpi_free(B);
	mpi_free(b);
	mpi_free(v);
	mpi_free(x);
	bytes_free(salt);
	mpi_free(k);
	mpi_free(g);
	mpi_free(N);
	return (success ? 0 : -1);
}


static int
ssrp_local_server_finalize(struct ssrp_server *server, const struct bytes *token)
{
	int success = 0;

	/* sanity checks */
	if (server == NULL || server->opaque == NULL || token == NULL)
		goto cleanup;

	struct ssrp_local_server_opaque *srvinfo = server->opaque;
	if (srvinfo->token == NULL || srvinfo->key == NULL)
		goto cleanup;

	/* compare the given token to the one we have */
	success = (bytes_timingsafe_bcmp(srvinfo->token, token) == 0);

	/* regardless of the result, forget the server's token */
	bytes_free(srvinfo->token);
	srvinfo->token = NULL;

	/* on failure, forget the server key too */
	if (!success) {
		bytes_free(srvinfo->key);
		srvinfo->key = NULL;
	}

	/* FALLTHROUGH */
cleanup:
	return (success ? 0 : -1);
}


static void
ssrp_local_server_free(struct ssrp_server *server)
{
	if (server == NULL)
		return;

	if (server->opaque != NULL) {
		struct ssrp_local_server_opaque *srvinfo = server->opaque;
		bytes_free(srvinfo->key);
		bytes_free(srvinfo->token);
		bytes_free(srvinfo->P);
		bytes_free(srvinfo->I);
		freezero(srvinfo, sizeof(struct ssrp_local_server_opaque));
	}
	freezero(server, sizeof(struct ssrp_server));
}


static int
ssrp_client_authenticate(struct ssrp_client *client, struct ssrp_server *server)
{
	struct mpi *N = NULL, *g = NULL, *k = NULL;
	struct mpi *a = NULL, *A = NULL, *B = NULL;
	struct mpi *u = NULL, *x = NULL, *S = NULL;
	struct bytes *salt = NULL;
	struct bytes *Sb = NULL, *K = NULL, *token = NULL;
	int success = 0;

	/* sanity checks */
	if (client == NULL || client->opaque == NULL || server == NULL)
		goto cleanup;

	if (srp_parameters(&N, &g, &k) != 0)
		goto cleanup;

	const struct ssrp_client_opaque *clientinfo = client->opaque;

	/* Send I, A=g**a % N (a la Diffie Hellman) */
	a = mpi_rand_range_from_one_to(N);
	A = mpi_mod_exp(g, a, N);
	if (server->start(server, clientinfo->I, A, &salt, &B, &u) != 0)
		goto cleanup;

	/* Generate string xH=SHA256(salt|password) */
	/* Convert xH to integer x somehow */
	x = srp_mpi_from_sha256_bytes(salt, clientinfo->P);

	/* Generrate S = B ** (a + u * x) % N */
	struct mpi *u_times_x = mpi_mul(u, x);
	struct mpi *a_plus_u_times_x = mpi_add(a, u_times_x);
	S = mpi_mod_exp(B, a_plus_u_times_x, N);
	mpi_free(a_plus_u_times_x);
	mpi_free(u_times_x);
	if (S == NULL)
		goto cleanup;

	/* Generate K = SHA256(S) */
	Sb = mpi_to_bytes_be(S);
	K  = sha256_hash(Sb);
	if (K == NULL)
		goto cleanup;

	/* generate and send the token to the server */
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
	mpi_free(S);
	mpi_free(x);
	mpi_free(u);
	bytes_free(salt);
	mpi_free(B);
	mpi_free(A);
	mpi_free(a);
	mpi_free(k);
	mpi_free(g);
	mpi_free(N);
	return (success ? 0 : -1);
}


static void
ssrp_client_free(struct ssrp_client *client)
{
	if (client == NULL)
		return;

	if (client->opaque != NULL) {
		struct ssrp_client_opaque *clientinfo = client->opaque;
		bytes_free(clientinfo->P);
		bytes_free(clientinfo->I);
		freezero(clientinfo, sizeof(struct ssrp_client_opaque));
	}
	bytes_free(client->key);
	freezero(client, sizeof(struct ssrp_client));
}
