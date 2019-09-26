/*
 * test_ssrp.c
 */
#include "munit.h"
#include "helpers.h"
#include "ssrp.h"
#include "test_srp.h"


static MunitResult
test_ssrp_local_server_new(const MunitParameter *params, void *data)
{
	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(srp_password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	struct ssrp_server *server = ssrp_local_server_new(I, P);
	munit_assert_not_null(server);
	munit_assert_not_null(server->opaque);
	const struct ssrp_local_server_opaque *srvinfo = server->opaque;
	munit_assert_int(bytes_bcmp(I, srvinfo->I), ==, 0);
	munit_assert_int(bytes_bcmp(P, srvinfo->P), ==, 0);
	munit_assert_null(srvinfo->key);
	munit_assert_null(srvinfo->token);

	server->free(server);
	bytes_free(P);
	bytes_free(I);
	return (MUNIT_OK);
}


static MunitResult
test_ssrp_client_new(const MunitParameter *params, void *data)
{
	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(srp_password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	struct ssrp_client *client = ssrp_client_new(I, P);
	munit_assert_not_null(client);
	munit_assert_not_null(client->opaque);
	const struct ssrp_client_opaque *clientinfo = client->opaque;
	munit_assert_int(bytes_bcmp(I, clientinfo->I), ==, 0);
	munit_assert_int(bytes_bcmp(P, clientinfo->P), ==, 0);
	munit_assert_null(client->key);

	client->free(client);
	bytes_free(P);
	bytes_free(I);
	return (MUNIT_OK);
}


/* Set 5 / Challenge 38 (Make sure the protocol works given a valid password) */
static MunitResult
test_local_ssrp_auth(const MunitParameter *params, void *data)
{
	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(srp_password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	struct ssrp_server *server = ssrp_local_server_new(I, P);
	if (server == NULL)
		munit_error("ssrp_local_server_new");

	struct ssrp_client *client = ssrp_client_new(I, P);
	if (client == NULL)
		munit_error("ssrp_client_new");

	const int ret = client->authenticate(client, server);

	munit_assert_int(ret, ==, 0);
	munit_assert_not_null(client->key);

	const struct ssrp_local_server_opaque *srvinfo = server->opaque;
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
test_local_ssrp_auth_wrong_password(const MunitParameter *params, void *data)
{
	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(srp_password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	struct ssrp_server *server = ssrp_local_server_new(I, P);
	if (server == NULL)
		munit_error("ssrp_local_server_new");

	/* change the client's password */
	struct bytes *client_P = bytes_from_str("Open Barley!");
	if (client_P == NULL)
		munit_error("byte_from_str");
	struct ssrp_client *client = ssrp_client_new(I, client_P);
	if (client == NULL)
		munit_error("ssrp_client_new");

	const int ret = client->authenticate(client, server);
	munit_assert_int(ret, ==, -1);
	munit_assert_null(client->key);

	const struct ssrp_local_server_opaque *srvinfo = server->opaque;
	munit_assert_not_null(server->opaque);
	munit_assert_null(srvinfo->key);
	munit_assert_null(srvinfo->token);

	client->free(client);
	server->free(server);
	bytes_free(client_P);
	bytes_free(P);
	bytes_free(I);
	return (MUNIT_OK);
}


static MunitResult
test_local_ssrp_auth_wrong_email(const MunitParameter *params, void *data)
{
	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(srp_password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	struct ssrp_server *server = ssrp_local_server_new(I, P);
	if (server == NULL)
		munit_error("ssrp_local_server_new");

	/* change the client's email */
	struct bytes *client_I = bytes_from_str("cassim@1001nights.com");
	if (client_I == NULL)
		munit_error("byte_from_str");

	struct ssrp_client *client = ssrp_client_new(client_I, P);
	if (client == NULL)
		munit_error("ssrp_client_new");

	const int ret = client->authenticate(client, server);
	munit_assert_int(ret, ==, -1);
	munit_assert_null(client->key);

	const struct ssrp_local_server_opaque *srvinfo = server->opaque;
	munit_assert_not_null(server->opaque);
	munit_assert_null(srvinfo->key);
	munit_assert_null(srvinfo->token);

	client->free(client);
	server->free(server);
	bytes_free(client_I);
	bytes_free(P);
	bytes_free(I);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_ssrp_suite_tests[] = {
	{ "server", test_ssrp_local_server_new, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "client", test_ssrp_client_new, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "local/auth",             test_local_ssrp_auth,                srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "local/wrong-password",   test_local_ssrp_auth_wrong_password, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "local/wrong-identifier", test_local_ssrp_auth_wrong_email,    srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
