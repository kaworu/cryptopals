/*
 * break_ssrp.c
 *
 * Simplified Secure Remote Password (SSRP) mitm stuff for cryptopals.com
 * challenges.
 */
#include <stdlib.h>
#include <string.h>

#include "compat.h"
#include "mac.h"
#include "sha256.h"
#include "srp.h"
#include "break_ssrp.h"


/* local struct ssrp_server method members implementations */
static int	ssrp_local_mitm_server_start(struct ssrp_server *server,
		    const struct bytes *I, const struct mpi *A,
		    struct bytes **salt_p, struct mpi **B_p, struct mpi **u_p);
static int	ssrp_local_mitm_server_finalize(struct ssrp_server *server,
		    const struct bytes *token);
static void	ssrp_local_mitm_server_free(struct ssrp_server *server);

/* password cracking helper */
static int	ssrp_local_mitm_test_password(const struct ssrp_server *server,
		    const char *guess);


struct ssrp_server *
ssrp_local_mitm_server_new(void)
{
	struct ssrp_server *server = NULL;
	int success = 0;

	server = calloc(1, sizeof(struct ssrp_server));
	if (server == NULL)
		goto cleanup;

	server->opaque = calloc(1, sizeof(struct ssrp_local_mitm_server_opaque));
	if (server->opaque == NULL)
		goto cleanup;

	success = 1;

	server->start    = ssrp_local_mitm_server_start;
	server->finalize = ssrp_local_mitm_server_finalize;
	server->free     = ssrp_local_mitm_server_free;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		ssrp_local_mitm_server_free(server);
		server = NULL;
	}
	return (server);
}


char *
ssrp_local_mitm_password(const struct ssrp_server *server,
		    const char **dict, size_t count)
{
	char *password = NULL;

	/* sanity checks */
	if (server == NULL || dict == NULL)
		goto cleanup;

	for (size_t i = 0; i < count && password == NULL; i++) {
		switch (ssrp_local_mitm_test_password(server, dict[i])) {
		case -1:
			goto cleanup;
		case 0:
			continue;
		default: /* succcess */
			password = strdup(dict[i]);
			if (password == NULL)
				goto cleanup;
			break;
		}
	}

	/* FALLTHROUGH */
cleanup:
	return (password);
}


static int
ssrp_local_mitm_server_start(struct ssrp_server *server, const struct bytes *I,
		    const struct mpi *A, struct bytes **salt_p,
		    struct mpi **B_p, struct mpi **u_p)
{
	struct mpi *N = NULL, *g = NULL;
	struct bytes *salt = NULL;
	struct mpi *B = NULL, *b = NULL, *u = NULL;
	/* server copy */
	struct bytes *salt_s = NULL;
	struct mpi *A_s = NULL, *B_s = NULL, *u_s = NULL;

	int success = 0;

	/* sanity checks */
	if (server == NULL || server->opaque == NULL)
		goto cleanup;
	if (I == NULL || A == NULL)
		goto cleanup;
	if (salt_p == NULL || B_p == NULL || u_p == NULL)
		goto cleanup;

	struct ssrp_local_mitm_server_opaque *srvinfo = server->opaque;

	/* we don't need k */
	if (srp_parameters(&N, &g, NULL) != 0)
		goto cleanup;

	/* Generate salt as random integer */
	salt = bytes_randomized(SRP_SALT_BYTES);
	if (salt == NULL)
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

	A_s    = mpi_dup(A);
	salt_s = bytes_dup(salt);
	B_s    = mpi_dup(B);
	u_s    = mpi_dup(u);
	if (A_s == NULL || salt_s == NULL || B_s == NULL || u_s == NULL)
		goto cleanup;

	success = 1;

	/* copy N, g, A, B, b, salt, and u into the server info for later use */
	mpi_free(srvinfo->N);
	srvinfo->N = N;
	N = NULL;
	mpi_free(srvinfo->g);
	srvinfo->g = g;
	g = NULL;
	mpi_free(srvinfo->A);
	srvinfo->A = A_s;
	A_s = NULL;
	bytes_free(srvinfo->salt);
	srvinfo->salt = salt_s;
	salt_s = NULL;
	mpi_free(srvinfo->B);
	srvinfo->B = B_s;
	B_s = NULL;
	mpi_free(srvinfo->b);
	srvinfo->b = b;
	b = NULL;
	mpi_free(srvinfo->u);
	srvinfo->u = u_s;
	u_s = NULL;

	/* set "return" values for the caller */
	*salt_p = salt;
	salt = NULL;
	*B_p = B;
	B = NULL;
	*u_p = u;
	u = NULL;

	/* FALLTHROUGH */
cleanup:
	mpi_free(u_s);
	mpi_free(B_s);
	bytes_free(salt_s);
	mpi_free(A_s);
	mpi_free(u);
	mpi_free(B);
	mpi_free(b);
	bytes_free(salt);
	mpi_free(g);
	mpi_free(N);
	return (success ? 0 : -1);
}


static int
ssrp_local_mitm_server_finalize(struct ssrp_server *server, const struct bytes *token)
{
	int success = 0;

	/* sanity checks */
	if (server == NULL || server->opaque == NULL)
		goto cleanup;

	struct ssrp_local_mitm_server_opaque *srvinfo = server->opaque;
	bytes_free(srvinfo->token);
	srvinfo->token = bytes_dup(token);
	if (srvinfo->token == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	return (success ? 0 : -1);
}


static void
ssrp_local_mitm_server_free(struct ssrp_server *server)
{
	if (server == NULL)
		return;

	if (server->opaque != NULL) {
		struct ssrp_local_mitm_server_opaque *srvinfo = server->opaque;
		mpi_free(srvinfo->N);
		mpi_free(srvinfo->g);
		bytes_free(srvinfo->salt);
		bytes_free(srvinfo->token);
		mpi_free(srvinfo->A);
		mpi_free(srvinfo->B);
		mpi_free(srvinfo->b);
		mpi_free(srvinfo->u);
		freezero(srvinfo, sizeof(struct ssrp_local_mitm_server_opaque));
	}
	freezero(server, sizeof(struct ssrp_server));
}


static int
ssrp_local_mitm_test_password(const struct ssrp_server *server,
		    const char *guess)
{
	struct bytes *password = NULL;
	struct mpi *x = NULL, *v = NULL, *S = NULL;
	struct bytes *Sb = NULL, *K = NULL;
	struct bytes *token = NULL;
	int success = 0, match = 0;

	/* sanity checks */
	if (server == NULL || server->opaque == NULL)
		goto cleanup;
	if (guess == NULL)
		goto cleanup;

	const struct ssrp_local_mitm_server_opaque *srvinfo = server->opaque;
	const struct bytes *salt =srvinfo->salt;
	const struct mpi *N =srvinfo->N;
	const struct mpi *g =srvinfo->g;
	const struct mpi *A =srvinfo->A;
	const struct mpi *B =srvinfo->B;
	const struct mpi *b =srvinfo->b;
	const struct mpi *u =srvinfo->u;

	/* more sanity checks */
	if (salt == NULL || srvinfo->token == NULL)
		goto cleanup;
	if (N == NULL || g == NULL)
		goto cleanup;
	if (A == NULL || B == NULL || b == NULL || u == NULL)
		goto cleanup;

	/* convert the guess string into a struct bytes */
	password = bytes_from_str(guess);
	if (password == NULL)
		goto cleanup;

	/* Generate string xH=SHA256(salt|password) */
	/* Convert xH to integer x somehow */
	x = srp_mpi_from_sha256_bytes(salt, password);
	if (x == NULL)
		goto cleanup;

	/* Generate v=g**x % N */
	v = mpi_mod_exp(g, x, N);
	if (v == NULL)
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
	/* NOTE: no worries about timing safety here */
	match = (bytes_bcmp(srvinfo->token, token) == 0);

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(token);
	bytes_free(K);
	bytes_free(Sb);
	mpi_free(S);
	mpi_free(v);
	mpi_free(x);
	bytes_free(password);
	if (!success)
		return -1;
	else
		return (match ? 1 : 0);
}
