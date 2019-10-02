/*
 * test_break_srp.c
 */
#include "munit.h"
#include "helpers.h"
#include "break_srp.h"

#include "test_srp.h"
#include "test_srp_py.h"


/* Set 5 / Challenge 37 */
static MunitResult
test_local_srp_spoof_with_0(const MunitParameter *params, void *data)
{
	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(srp_password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	struct srp_server *server = srp_local_server_new(I, P);
	if (server == NULL)
		munit_error("srp_local_server_new");

	struct srp_client *client =
		    srp_spoof_client_new(SRP_SPOOF_CLIENT_0_AS_A, I);
	if (client == NULL)
		munit_error("srp_spoof_client_new");

	const int ret = client->authenticate(client, server);

	munit_assert_int(ret, ==, 0);
	munit_assert_not_null(client->key);

	const struct srp_local_server_opaque *srvinfo = server->opaque;
	munit_assert_not_null(server->opaque);
	munit_assert_not_null(srvinfo->key);
	munit_assert_null(srvinfo->token);
	munit_assert_size(client->key->len, ==, srvinfo->key->len);
	munit_assert_memory_equal(client->key->len,
		    client->key->data, srvinfo->key->data);

	client->free(client);
	server->free(server);
	bytes_free(P);
	bytes_free(I);
	return (MUNIT_OK);
}


static MunitResult
test_local_srp_spoof_with_N(const MunitParameter *params, void *data)
{
	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(srp_password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	struct srp_server *server = srp_local_server_new(I, P);
	if (server == NULL)
		munit_error("srp_local_server_new");

	struct srp_client *client =
		    srp_spoof_client_new(SRP_SPOOF_CLIENT_N_AS_A, I);
	if (client == NULL)
		munit_error("srp_spoof_client_new");

	const int ret = client->authenticate(client, server);

	munit_assert_int(ret, ==, 0);
	munit_assert_not_null(client->key);

	const struct srp_local_server_opaque *srvinfo = server->opaque;
	munit_assert_not_null(server->opaque);
	munit_assert_not_null(srvinfo->key);
	munit_assert_null(srvinfo->token);
	munit_assert_size(client->key->len, ==, srvinfo->key->len);
	munit_assert_memory_equal(client->key->len,
		    client->key->data, srvinfo->key->data);

	client->free(client);
	server->free(server);
	bytes_free(P);
	bytes_free(I);
	return (MUNIT_OK);
}


static MunitResult
test_py_srp_spoof_with_0(const MunitParameter *params, void *data)
{
	const struct py_srp_server_settings *py_server = data;

	if (py_server == NULL)
		return (MUNIT_SKIP);

	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(srp_password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	const char *hostname = munit_parameters_get(params, "srp_hostname");
	const char *port     = munit_parameters_get(params, "srp_port");
	struct srp_server *server = srp_remote_server_new(hostname, port);
	if (server == NULL)
		munit_error("srp_remote_server_new");

	struct srp_client *client =
		    srp_spoof_client_new(SRP_SPOOF_CLIENT_0_AS_A, I);
	if (client == NULL)
		munit_error("srp_spoof_client_new");

	const int ret = client->authenticate(client, server);

	munit_assert_int(ret, ==, 0);
	munit_assert_not_null(client->key);

	client->free(client);
	server->free(server);
	bytes_free(P);
	bytes_free(I);
	return (MUNIT_OK);
}


static MunitResult
test_py_srp_spoof_with_N(const MunitParameter *params, void *data)
{
	const struct py_srp_server_settings *py_server = data;

	if (py_server == NULL)
		return (MUNIT_SKIP);

	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(srp_password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	const char *hostname = munit_parameters_get(params, "srp_hostname");
	const char *port     = munit_parameters_get(params, "srp_port");
	struct srp_server *server = srp_remote_server_new(hostname, port);
	if (server == NULL)
		munit_error("srp_remote_server_new");

	struct srp_client *client =
		    srp_spoof_client_new(SRP_SPOOF_CLIENT_N_AS_A, I);
	if (client == NULL)
		munit_error("srp_spoof_client_new");

	const int ret = client->authenticate(client, server);

	munit_assert_int(ret, ==, 0);
	munit_assert_not_null(client->key);

	client->free(client);
	server->free(server);
	bytes_free(P);
	bytes_free(I);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_break_srp_suite_tests[] = {
	{ "local/spoof-0", test_local_srp_spoof_with_0, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "local/spoof-N", test_local_srp_spoof_with_N, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = "py/spoof-0",
		.test       = test_py_srp_spoof_with_0,
		.setup      = py_srp_server_setup,
		.tear_down  = py_srp_server_tear_down,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = test_srp_py_server_params,
	},
	{
		.name       = "py/spoof-N",
		.test       = test_py_srp_spoof_with_N,
		.setup      = py_srp_server_setup,
		.tear_down  = py_srp_server_tear_down,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = test_srp_py_server_params,
	},
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
