/*
 * test_srp.c
 */
#include "munit.h"
#include "helpers.h"
#include "srp.h"
#include "test_srp.h"


static MunitResult
test_srp_parameters(const MunitParameter *params, void *data)
{
	struct bignum *expected_N = bignum_from_hex(srp_nist_prime_hex);
	struct bignum *expected_g = bignum_from_hex(srp_g_hex);
	struct bignum *expected_k = bignum_from_hex(srp_k_hex);
	if (expected_N == NULL || expected_g == NULL || expected_k == NULL)
		munit_error("bignum_from_hex");

	struct bignum *N = NULL, *g = NULL, *k = NULL;
	const int ret = srp_parameters(&N, &g, &k);

	munit_assert_int(ret, ==, 0);
	munit_assert_not_null(N);
	munit_assert_not_null(g);
	munit_assert_not_null(k);
	munit_assert_int(bignum_cmp(expected_N, N), ==, 0);
	munit_assert_int(bignum_cmp(expected_g, g), ==, 0);
	munit_assert_int(bignum_cmp(expected_k, k), ==, 0);

	/* XXX: not testing that passing NULL is OK */

	bignum_free(k);
	bignum_free(g);
	bignum_free(N);
	bignum_free(expected_k);
	bignum_free(expected_g);
	bignum_free(expected_N);
	return (MUNIT_OK);
}


static MunitResult
test_srp_server_new(const MunitParameter *params, void *data)
{
	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(srp_password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	struct srp_server *server = srp_server_new(I, P);
	munit_assert_not_null(server);
	munit_assert_int(bytes_bcmp(I, server->I), ==, 0);
	munit_assert_int(bytes_bcmp(P, server->P), ==, 0);

	munit_assert_not_null(server->opaque);
	const struct srp_server_opaque *ad = server->opaque;
	munit_assert_null(ad->key);
	munit_assert_null(ad->token);

	server->free(server);
	bytes_free(P);
	bytes_free(I);
	return (MUNIT_OK);
}


static MunitResult
test_srp_client_new(const MunitParameter *params, void *data)
{
	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(srp_password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	struct srp_client *client = srp_client_new(I, P);
	munit_assert_not_null(client);
	munit_assert_int(bytes_bcmp(I, client->I), ==, 0);
	munit_assert_int(bytes_bcmp(P, client->P), ==, 0);
	munit_assert_null(client->key);

	client->free(client);
	bytes_free(P);
	bytes_free(I);
	return (MUNIT_OK);
}


/* Set 5 / Challenge 36 */
static MunitResult
test_srp_auth(const MunitParameter *params, void *data)
{
	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(srp_password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	struct srp_server *server = srp_server_new(I, P);
	if (server == NULL)
		munit_error("srp_server_new");

	struct srp_client *client = srp_client_new(I, P);
	if (client == NULL)
		munit_error("srp_client_new");

	const int ret = client->authenticate(client, server);

	munit_assert_int(ret, ==, 0);
	munit_assert_not_null(client->key);

	munit_assert_not_null(server->opaque);
	const struct srp_server_opaque *ad = server->opaque;
	munit_assert_not_null(ad->key);
	munit_assert_null(ad->token);

	munit_assert_size(client->key->len, ==, ad->key->len);
	munit_assert_memory_equal(client->key->len,
		    client->key->data, ad->key->data);

	client->free(client);
	server->free(server);
	bytes_free(P);
	bytes_free(I);
	return (MUNIT_OK);
}


static MunitResult
test_srp_auth_wrong_password(const MunitParameter *params, void *data)
{
	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(srp_password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	struct srp_server *server = srp_server_new(I, P);
	if (server == NULL)
		munit_error("srp_server_new");

	/* change the client's password */
	struct bytes *client_P = bytes_from_str("Open Barley!");
	if (client_P == NULL)
		munit_error("byte_from_str");

	struct srp_client *client = srp_client_new(I, client_P);
	if (client == NULL)
		munit_error("srp_client_new");

	const int ret = client->authenticate(client, server);
	munit_assert_int(ret, ==, -1);
	munit_assert_null(client->key);

	munit_assert_not_null(server->opaque);
	const struct srp_server_opaque *ad = server->opaque;
	munit_assert_null(ad->key);
	munit_assert_null(ad->token);

	client->free(client);
	server->free(server);
	bytes_free(client_P);
	bytes_free(P);
	bytes_free(I);
	return (MUNIT_OK);
}


static MunitResult
test_srp_auth_wrong_email(const MunitParameter *params, void *data)
{
	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(srp_password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	struct srp_server *server = srp_server_new(I, P);
	if (server == NULL)
		munit_error("srp_server_new");

	/* change the client's email */
	struct bytes *client_I = bytes_from_str("cassim@1001nights.com");
	if (client_I == NULL)
		munit_error("byte_from_str");

	struct srp_client *client = srp_client_new(client_I, P);
	if (client == NULL)
		munit_error("srp_client_new");

	const int ret = client->authenticate(client, server);
	munit_assert_int(ret, ==, -1);
	munit_assert_null(client->key);

	munit_assert_not_null(server->opaque);
	const struct srp_server_opaque *ad = server->opaque;
	munit_assert_null(ad->key);
	munit_assert_null(ad->token);

	client->free(client);
	server->free(server);
	bytes_free(client_I);
	bytes_free(P);
	bytes_free(I);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_srp_suite_tests[] = {
	{ "params", test_srp_parameters, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
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
