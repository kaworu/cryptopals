/*
 * test_break_ssrp.c
 */
#include "munit.h"
#include "helpers.h"
#include "ssrp.h"
#include "break_ssrp.h"

#include "test_srp.h"
#include "test_break_ssrp.h"


static const char *
random_password(void)
{
	const int index = munit_rand_int_range(0, passwordslen);
	return passwords[index];
}


static MunitResult
test_ssrp_local_mitm_server_new(const MunitParameter *params, void *data)
{
	struct ssrp_server *server = ssrp_local_mitm_server_new();
	munit_assert_not_null(server);
	munit_assert_not_null(server->opaque);
	const struct ssrp_local_mitm_server_opaque *srvinfo = server->opaque;
	munit_assert_null(srvinfo->salt);
	munit_assert_null(srvinfo->token);
	munit_assert_null(srvinfo->A);
	munit_assert_null(srvinfo->B);
	munit_assert_null(srvinfo->u);

	server->free(server);
	return (MUNIT_OK);
}


static MunitResult
test_ssrp_local_mitm_crack(const MunitParameter *params, void *data)
{
	const char *password = random_password();
	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	struct ssrp_server *server = ssrp_local_mitm_server_new();
	if (server == NULL)
		munit_error("ssrp_local_mitm_server_new");

	struct ssrp_client *client = ssrp_client_new(I, P);
	if (client == NULL)
		munit_error("ssrp_client_new");

	const int ret = client->authenticate(client, server);

	munit_assert_int(ret, ==, 0);
	munit_assert_not_null(client->key);
	const struct ssrp_local_mitm_server_opaque *srvinfo = server->opaque;
	munit_assert_not_null(srvinfo->salt);
	munit_assert_not_null(srvinfo->token);
	munit_assert_not_null(srvinfo->A);
	munit_assert_not_null(srvinfo->B);
	munit_assert_not_null(srvinfo->u);

	char *guess = ssrp_local_mitm_password(server, passwords, passwordslen);
	munit_assert_not_null(guess);
	munit_assert_size(strlen(guess), ==, strlen(password));
	munit_assert_memory_equal(strlen(password), password, guess);

	free(guess);
	client->free(client);
	server->free(server);
	bytes_free(P);
	bytes_free(I);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_break_ssrp_suite_tests[] = {
	{ "server",      test_ssrp_local_mitm_server_new, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "local/crack", test_ssrp_local_mitm_crack,      srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
