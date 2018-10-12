/*
 * test_srp.c
 */
#include "munit.h"
#include "helpers.h"
#include "srp.h"
#include "test_srp.h"


/* helpers to generate testing parameters from Set 5 / Challenge 36 */

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


static struct srp_params *
my_testing_srp_params_new(void)
{
	struct bignum *N, *g, *k;
	struct bytes *I, *P;
	my_testing_srp_parameters(&N, &g, &k, &I, &P);

	struct srp_params *params = srp_params_new(N, g, k, I, P);
	if (params == NULL)
		munit_error("srp_params_new");

	bytes_free(P);
	bytes_free(I);
	bignum_free(k);
	bignum_free(g);
	bignum_free(N);
	return (params);
}


static void
my_assert_srp_params(const struct srp_params *params, const struct bignum *N,
		    const struct bignum *g, const struct bignum *k,
		    const struct bytes *I, const struct bytes *P)
{
	munit_assert_not_null(params);
	munit_assert_int(bignum_cmp(N, params->N), ==, 0);
	munit_assert_int(bignum_cmp(g, params->g), ==, 0);
	munit_assert_int(bignum_cmp(k, params->k), ==, 0);
	munit_assert_int(bytes_bcmp(I, params->I), ==, 0);
	munit_assert_int(bytes_bcmp(P, params->P), ==, 0);
}


static void
my_assert_srp_params_eq(const struct srp_params *x, const struct srp_params *y)
{
	munit_assert_not_null(x);
	munit_assert_not_null(y);
	my_assert_srp_params(x, y->N, y->g, y->k, y->I, y->P);
}


static MunitResult
test_srp_params_new(const MunitParameter *munit_params, void *data)
{
	struct bignum *N, *g, *k;
	struct bytes *I, *P;
	my_testing_srp_parameters(&N, &g, &k, &I, &P);

	struct srp_params *params = srp_params_new(N, g, k, I, P);
	my_assert_srp_params(params, N, g, k, I, P);

	srp_params_free(params);
	bytes_free(I);
	bytes_free(P);
	bignum_free(k);
	bignum_free(g);
	bignum_free(N);
	return (MUNIT_OK);
}


static MunitResult
test_srp_params_dup(const MunitParameter *munit_params, void *data)
{
	struct srp_params *params = my_testing_srp_params_new();
	if (params == NULL)
		munit_error("my_testing_srp_params_new");

	struct srp_params *cpy = srp_params_dup(params);
	munit_assert_not_null(cpy);
	my_assert_srp_params_eq(params, cpy);

	srp_params_free(cpy);
	srp_params_free(params);
	return (MUNIT_OK);
}


static MunitResult
test_srp_server_new(const MunitParameter *munit_params, void *data)
{
	struct srp_params *params = my_testing_srp_params_new();
	if (params == NULL)
		munit_error("my_testing_srp_params_new");

	struct srp_server *server = srp_server_new(params);
	munit_assert_not_null(server);
	my_assert_srp_params_eq(params, server->params);
	munit_assert_null(server->key);
	munit_assert_null(server->token);

	srp_server_free(server);
	srp_params_free(params);
	return (MUNIT_OK);
}


static MunitResult
test_srp_client_new(const MunitParameter *munit_params, void *data)
{
	struct srp_params *params = my_testing_srp_params_new();
	if (params == NULL)
		munit_error("my_testing_srp_params_new");

	struct srp_client *client = srp_client_new(params);
	munit_assert_not_null(client);
	my_assert_srp_params_eq(params, client->params);
	munit_assert_null(client->key);

	srp_client_free(client);
	srp_params_free(params);
	return (MUNIT_OK);
}


/* Set 5 / Challenge 36 */
static MunitResult
test_srp_auth(const MunitParameter *munit_params, void *data)
{
	struct srp_params *params = my_testing_srp_params_new();
	if (params == NULL)
		munit_error("my_testing_srp_params_new");

	struct srp_server *server = srp_server_new(params);
	if (server == NULL)
		munit_error("srp_server_new");

	struct srp_client *client = srp_client_new(params);
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
	srp_params_free(params);
	return (MUNIT_OK);
}


static MunitResult
test_srp_auth_wrong_password(const MunitParameter *munit_params, void *data)
{
	struct srp_params *params = my_testing_srp_params_new();
	if (params == NULL)
		munit_error("my_testing_srp_params_new");

	struct srp_server *server = srp_server_new(params);
	if (server == NULL)
		munit_error("srp_server_new");

	/* change the client's password */
	bytes_free(params->P);
	params->P = bytes_from_str("Open Barley!");
	if (params->P == NULL)
		munit_error("byte_from_str");

	struct srp_client *client = srp_client_new(params);
	if (client == NULL)
		munit_error("srp_client_new");

	const int ret = client->authenticate(client, server);
	munit_assert_int(ret, ==, -1);
	munit_assert_null(client->key);
	munit_assert_null(server->key);
	munit_assert_null(server->token);

	srp_client_free(client);
	srp_server_free(server);
	srp_params_free(params);
	return (MUNIT_OK);
}


static MunitResult
test_srp_auth_wrong_email(const MunitParameter *munit_params, void *data)
{
	struct srp_params *params = my_testing_srp_params_new();
	if (params == NULL)
		munit_error("my_testing_srp_params_new");

	struct srp_server *server = srp_server_new(params);
	if (server == NULL)
		munit_error("srp_server_new");

	/* change the client's email */
	bytes_free(params->I);
	params->I = bytes_from_str("cassim@1001nights.com");
	if (params->I == NULL)
		munit_error("byte_from_str");

	struct srp_client *client = srp_client_new(params);
	if (client == NULL)
		munit_error("srp_client_new");

	const int ret = client->authenticate(client, server);
	munit_assert_int(ret, ==, -1);
	munit_assert_null(client->key);
	munit_assert_null(server->key);
	munit_assert_null(server->token);

	srp_client_free(client);
	srp_server_free(server);
	srp_params_free(params);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_srp_suite_tests[] = {
	{ "params/new", test_srp_params_new, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "params/dup", test_srp_params_dup, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "server/new", test_srp_server_new, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "client/new", test_srp_client_new, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
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
