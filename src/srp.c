/*
 * srp.c
 *
 * Secure Remote Password (SRP) stuff for cryptopals.com challenges.
 */
#include <stdlib.h>

#include "compat.h"
#include "sha256.h"
#include "mac.h"
#include "srp.h"


/*
 * 32 bytes long salt, inspired by the test vectors from SRP for TLS
 * Authentication (see https://tools.ietf.org/html/rfc5054#appendix-B).
 */
#define	SRP_SALT_BYTES	32


/* struct srp_server method members implementations */
static int	srp_local_server_start(struct srp_server *server,
		    const struct bytes *I, const struct bignum *A,
		    struct bytes **salt_p, struct bignum **B_p);
static int	srp_local_server_finalize(struct srp_server *server,
		    const struct bytes *token);
static void	srp_local_server_free(struct srp_server *server);
/* struct srp_client method members implementations */
static int	srp_client_authenticate(struct srp_client *client,
		    struct srp_server *server);
static void	srp_client_free(struct srp_client *client);

/* helpers to get a bignum from SHA-256(lhs concatenated to rhs) */
static struct bignum	*srp_bignum_from_sha256_bytes(
		    const struct bytes *lhs, const struct bytes *rhs);
static struct bignum	*srp_bignum_from_sha256_bignums(
		    const struct bignum *lhs, const struct bignum *rhs);


int
srp_parameters(struct bignum **N_p, struct bignum **g_p, struct bignum **k_p)
{
	struct bignum *N = NULL, *g = NULL, *k = NULL;
	int success = 0;

	N = bignum_from_hex(
		"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
		"fffffffffffff");
	g = bignum_from_hex("2");
	k = bignum_from_hex("3");

	if (N == NULL || g == NULL || k == NULL)
		goto cleanup;

	success = 1;

	if (N_p != NULL) {
		*N_p = N;
		N = NULL;
	}
	if (g_p != NULL) {
		*g_p = g;
		g = NULL;
	}
	if (k_p != NULL) {
		*k_p = k;
		k = NULL;
	}
	/* FALLTHROUGH */
cleanup:
	bignum_free(k);
	bignum_free(g);
	bignum_free(N);
	return (success ? 0 : -1);
}


struct srp_server *
srp_local_server_new(const struct bytes *I, const struct bytes *P)
{
	struct srp_server *server = NULL;
	int success = 0;

	/* sanity checks */
	if (I == NULL || P == NULL)
		goto cleanup;

	server = calloc(1, sizeof(struct srp_server));
	if (server == NULL)
		goto cleanup;

	server->opaque = calloc(1, sizeof(struct srp_local_server_opaque));
	if (server->opaque == NULL)
		goto cleanup;
	struct srp_local_server_opaque *srvinfo = server->opaque;

	srvinfo->I = bytes_dup(I);
	srvinfo->P = bytes_dup(P);
	if (srvinfo->I == NULL || srvinfo->P == NULL)
		goto cleanup;

	server->start    = srp_local_server_start;
	server->finalize = srp_local_server_finalize;
	server->free     = srp_local_server_free;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		srp_local_server_free(server);
		server = NULL;
	}
	return (server);
}


struct srp_client *
srp_client_new(const struct bytes *I, const struct bytes *P)
{
	struct srp_client *client = NULL;
	int success = 0;

	/* sanity checks */
	if (I == NULL || P == NULL)
		goto cleanup;

	client = calloc(1, sizeof(struct srp_client));
	if (client == NULL)
		goto cleanup;

	client->I = bytes_dup(I);
	client->P = bytes_dup(P);
	if (client->I == NULL || client->P == NULL)
		goto cleanup;

	client->authenticate = srp_client_authenticate;
	client->free         = srp_client_free;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		srp_client_free(client);
		client = NULL;
	}
	return (client);
}


static int
srp_local_server_start(struct srp_server *server,
		    const struct bytes *I, const struct bignum *A,
		    struct bytes **salt_p, struct bignum **B_p)
{
	struct bignum *N = NULL, *g = NULL, *k = NULL;
	struct bytes *salt = NULL;
	struct bignum *x = NULL, *v = NULL;
	struct bignum *b = NULL, *B = NULL;
	struct bignum *u = NULL, *S = NULL;
	struct bytes *Sb = NULL, *K = NULL;
	struct bytes *token = NULL;
	int success = 0;

	/* sanity checks */
	if (server == NULL || server->opaque == NULL)
		goto cleanup;
	if (I == NULL || A == NULL)
		goto cleanup;
	if (salt_p == NULL || B_p == NULL)
		goto cleanup;

	if (srp_parameters(&N, &g, &k) != 0)
		goto cleanup;

	struct srp_local_server_opaque *srvinfo = server->opaque;

	/* ensure that I is the correct email */
	if (bytes_timingsafe_bcmp(srvinfo->I, I) != 0)
		goto cleanup;

	/* Generate salt as random integer */
	salt = bytes_randomized(SRP_SALT_BYTES);
	if (salt == NULL)
		goto cleanup;

	/* Generate string xH=SHA256(salt|password) */
	/* Convert xH to integer x somehow */
	x = srp_bignum_from_sha256_bytes(salt, srvinfo->P);
	if (x == NULL)
		goto cleanup;

	/* Generate v=g**x % N */
	v = bignum_modexp(g, x, N);
	if (v == NULL)
		goto cleanup;

	/* B=kv + g**b % N */
	b = bignum_rand(N);
	struct bignum *kv = bignum_mod_mul(k, v, N);
	struct bignum *g_pow_b = bignum_modexp(g, b, N);
	B = bignum_mod_add(kv, g_pow_b, N);
	bignum_free(g_pow_b);
	bignum_free(kv);
	if (B == NULL)
		goto cleanup;

	/* Compute string uH = SHA256(A|B), u = integer of uH */
	u = srp_bignum_from_sha256_bignums(A, B);
	if (u == NULL)
		goto cleanup;

	/* Generate S = (A * v**u) ** b % N */
	struct bignum *v_pow_u = bignum_modexp(v, u, N);
	struct bignum *A_times_v_pow_u = bignum_mod_mul(A, v_pow_u, N);
	S = bignum_modexp(A_times_v_pow_u, b, N);
	bignum_free(A_times_v_pow_u);
	bignum_free(v_pow_u);
	if (S == NULL)
		goto cleanup;

	/* Generate K = SHA256(S) */
	Sb = bignum_to_bytes_be(S);
	K  = sha256_hash(Sb);
	if (K == NULL)
		goto cleanup;

	/* generate the HMAC-SHA256(K, salt) token */
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

	/* FALLTHROUGH */
cleanup:
	bytes_free(token);
	bytes_free(K);
	bytes_free(Sb);
	bignum_free(S);
	bignum_free(u);
	bignum_free(B);
	bignum_free(b);
	bignum_free(v);
	bignum_free(x);
	bytes_free(salt);
	bignum_free(k);
	bignum_free(g);
	bignum_free(N);
	return (success ? 0 : -1);
}


static int
srp_local_server_finalize(struct srp_server *server, const struct bytes *token)
{
	int success = 0;

	/* sanity checks */
	if (server == NULL || server->opaque == NULL || token == NULL)
		goto cleanup;

	struct srp_local_server_opaque *srvinfo = server->opaque;
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
srp_local_server_free(struct srp_server *server)
{
	if (server == NULL)
		return;

	if (server->opaque) {
		struct srp_local_server_opaque *srvinfo = server->opaque;
		bytes_free(srvinfo->key);
		bytes_free(srvinfo->token);
		bytes_free(srvinfo->I);
		bytes_free(srvinfo->P);
		freezero(srvinfo, sizeof(struct srp_local_server_opaque));
	}
	freezero(server, sizeof(struct srp_server));
}


static int
srp_client_authenticate(struct srp_client *client, struct srp_server *server)
{
	struct bignum *N = NULL, *g = NULL, *k = NULL;
	struct bignum *a = NULL, *A = NULL, *B = NULL;
	struct bignum *u = NULL, *x = NULL, *S = NULL;
	struct bytes *salt = NULL;
	struct bytes *Sb = NULL, *K = NULL, *token = NULL;
	int success = 0;

	/* sanity checks */
	if (client == NULL || server == NULL)
		goto cleanup;

	if (srp_parameters(&N, &g, &k) != 0)
		goto cleanup;

	/* Send I, A=g**a % N (a la Diffie Hellman) */
	a = bignum_rand(N);
	A = bignum_modexp(g, a, N);
	if (server->start(server, client->I, A, &salt, &B) != 0)
		goto cleanup;

	/* Compute string uH = SHA256(A|B), u = integer of uH */
	u = srp_bignum_from_sha256_bignums(A, B);
	if (u == NULL)
		goto cleanup;

	/* Generate string xH=SHA256(salt|password) */
	/* Convert xH to integer x somehow */
	x = srp_bignum_from_sha256_bytes(salt, client->P);

	/* Generate S = (B - k * g**x)**(a + u * x) % N */
	struct bignum *g_pow_x = bignum_modexp(g, x, N);
	struct bignum *k_times_g_pow_x = bignum_mod_mul(k, g_pow_x, N);
	struct bignum *lhs = bignum_sub(B, k_times_g_pow_x);
	struct bignum *u_times_x = bignum_mod_mul(u, x, N);
	struct bignum *rhs = bignum_mod_add(a, u_times_x, N);
	S = bignum_modexp(lhs, rhs, N);
	bignum_free(rhs);
	bignum_free(u_times_x);
	bignum_free(lhs);
	bignum_free(k_times_g_pow_x);
	bignum_free(g_pow_x);
	if (S == NULL)
		goto cleanup;

	/* Generate K = SHA256(S) */
	Sb = bignum_to_bytes_be(S);
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
	bignum_free(S);
	bignum_free(x);
	bignum_free(u);
	bytes_free(salt);
	bignum_free(B);
	bignum_free(A);
	bignum_free(a);
	bignum_free(k);
	bignum_free(g);
	bignum_free(N);
	return (success ? 0 : -1);
}


static void
srp_client_free(struct srp_client *client)
{
	if (client == NULL)
		return;

	bytes_free(client->I);
	bytes_free(client->P);
	bytes_free(client->key);
	freezero(client, sizeof(struct srp_client));
}


static struct bignum *
srp_bignum_from_sha256_bytes(const struct bytes *lhs, const struct bytes *rhs)
{
	struct bytes *lhs_rhs = NULL, *hash = NULL;
	struct bignum *num = NULL;

	lhs_rhs = bytes_joined(2, lhs, rhs);
	hash = sha256_hash(lhs_rhs);
	num = bignum_from_bytes_be(hash);

	bytes_free(hash);
	bytes_free(lhs_rhs);
	return (num);
}


static struct bignum *
srp_bignum_from_sha256_bignums(const struct bignum *lhs,
		    const struct bignum *rhs)
{
	struct bytes *blhs = bignum_to_bytes_be(lhs);
	struct bytes *brhs = bignum_to_bytes_be(rhs);
	struct bignum *num = srp_bignum_from_sha256_bytes(blhs, brhs);

	bytes_free(blhs);
	bytes_free(brhs);
	return (num);
}
