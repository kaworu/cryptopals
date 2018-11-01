/*
 * test_srp.c
 */
#include "munit.h"
#include "helpers.h"
#include "srp.h"
#include "test_srp.h"


/* helper to generate testing parameters from Set 5 / Challenge 36 */

static void
my_testing_srp_parameters(struct bignum **N_p, struct bignum **g_p, struct bignum **k_p,
		    struct bytes **I_p, struct bytes **P_p)
{
	struct bignum *N = bignum_from_hex(srp_nist_prime_hex);
	struct bignum *g = bignum_from_hex(srp_g_hex);
	struct bignum *k = bignum_from_hex(srp_k_hex);
	if (N == NULL || g == NULL || k == NULL)
		munit_error("bignum_from_hex");

	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(srp_password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	*N_p = N;
	*g_p = g;
	*k_p = k;
	*I_p = I;
	*P_p = P;
}


static MunitResult
test_srp_server_new(const MunitParameter *params, void *data)
{
	struct bignum *N, *g, *k;
	struct bytes  *I, *P;

	my_testing_srp_parameters(&N, &g, &k, &I, &P);

	struct srp_server *server = srp_server_new(N, g, k, I, P);
	munit_assert_not_null(server);
	munit_assert_int(bignum_cmp(N, server->N), ==, 0);
	munit_assert_int(bignum_cmp(g, server->g), ==, 0);
	munit_assert_int(bignum_cmp(k, server->k), ==, 0);
	munit_assert_int(bytes_bcmp(I, server->I), ==, 0);
	munit_assert_int(bytes_bcmp(P, server->P), ==, 0);
	munit_assert_null(server->key);
	munit_assert_null(server->token);

	srp_server_free(server);
	bytes_free(P);
	bytes_free(I);
	bignum_free(k);
	bignum_free(g);
	bignum_free(N);
	return (MUNIT_OK);
}


static MunitResult
test_srp_client_new(const MunitParameter *params, void *data)
{
	struct bignum *N, *g, *k;
	struct bytes  *I, *P;

	my_testing_srp_parameters(&N, &g, &k, &I, &P);

	struct srp_client *client = srp_client_new(N, g, k, I, P);
	munit_assert_not_null(client);
	munit_assert_int(bignum_cmp(N, client->N), ==, 0);
	munit_assert_int(bignum_cmp(g, client->g), ==, 0);
	munit_assert_int(bignum_cmp(k, client->k), ==, 0);
	munit_assert_int(bytes_bcmp(I, client->I), ==, 0);
	munit_assert_int(bytes_bcmp(P, client->P), ==, 0);
	munit_assert_null(client->key);

	srp_client_free(client);
	bytes_free(P);
	bytes_free(I);
	bignum_free(k);
	bignum_free(g);
	bignum_free(N);
	return (MUNIT_OK);
}


/* Set 5 / Challenge 36 */
static MunitResult
test_srp_auth(const MunitParameter *params, void *data)
{
	struct bignum *N, *g, *k;
	struct bytes  *I, *P;

	my_testing_srp_parameters(&N, &g, &k, &I, &P);

	struct srp_server *server = srp_server_new(N, g, k, I, P);
	if (server == NULL)
		munit_error("srp_server_new");

	struct srp_client *client = srp_client_new(N, g, k, I, P);
	if (client == NULL)
		munit_error("srp_client_new");

	const int ret = client->authenticate(client, server);
	munit_assert_int(ret, ==, 0);
	munit_assert_not_null(client->key);
	munit_assert_not_null(server->key);
	munit_assert_null(server->token);
	munit_assert_size(client->key->len, ==, server->key->len);
	munit_assert_memory_equal(client->key->len,
		    client->key->data, server->key->data);

	srp_client_free(client);
	srp_server_free(server);
	bytes_free(P);
	bytes_free(I);
	bignum_free(k);
	bignum_free(g);
	bignum_free(N);
	return (MUNIT_OK);
}


static MunitResult
test_srp_auth_wrong_password(const MunitParameter *params, void *data)
{
	struct bignum *N, *g, *k;
	struct bytes  *I, *P;

	my_testing_srp_parameters(&N, &g, &k, &I, &P);

	struct srp_server *server = srp_server_new(N, g, k, I, P);
	if (server == NULL)
		munit_error("srp_server_new");

	/* change the client's password */
	struct bytes *client_P = bytes_from_str("Open Barley!");
	if (client_P == NULL)
		munit_error("byte_from_str");

	struct srp_client *client = srp_client_new(N, g, k, I, client_P);
	if (client == NULL)
		munit_error("srp_client_new");

	const int ret = client->authenticate(client, server);
	munit_assert_int(ret, ==, -1);
	munit_assert_null(client->key);
	munit_assert_null(server->key);
	munit_assert_null(server->token);

	srp_client_free(client);
	srp_server_free(server);
	bytes_free(client_P);
	bytes_free(P);
	bytes_free(I);
	bignum_free(k);
	bignum_free(g);
	bignum_free(N);
	return (MUNIT_OK);
}


static MunitResult
test_srp_auth_wrong_email(const MunitParameter *params, void *data)
{
	struct bignum *N, *g, *k;
	struct bytes  *I, *P;

	my_testing_srp_parameters(&N, &g, &k, &I, &P);

	struct srp_server *server = srp_server_new(N, g, k, I, P);
	if (server == NULL)
		munit_error("srp_server_new");

	/* change the client's email */
	struct bytes *client_I = bytes_from_str("cassim@1001nights.com");
	if (client_I == NULL)
		munit_error("byte_from_str");

	struct srp_client *client = srp_client_new(N, g, k, client_I, P);
	if (client == NULL)
		munit_error("srp_client_new");

	const int ret = client->authenticate(client, server);
	munit_assert_int(ret, ==, -1);
	munit_assert_null(client->key);
	munit_assert_null(server->key);
	munit_assert_null(server->token);

	srp_client_free(client);
	srp_server_free(server);
	bytes_free(client_I);
	bytes_free(P);
	bytes_free(I);
	bignum_free(k);
	bignum_free(g);
	bignum_free(N);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_srp_suite_tests[] = {
	{ "server", test_srp_server_new, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "client", test_srp_client_new, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "auth-0",     test_srp_auth,                srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "auth-1",     test_srp_auth_wrong_password, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "auth-2",     test_srp_auth_wrong_email,    srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
