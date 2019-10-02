/*
 * test_srp.c
 */
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include "munit.h"
#include "helpers.h"
#include "srp.h"
#include "test_dh.h"
#include "test_srp.h"
#include "test_srp_py.h"


void *
py_srp_server_setup(const MunitParameter *params, void *user_data)
{
	const char *exec     = munit_parameters_get(params, "srp_server");
	const char *hostname = munit_parameters_get(params, "srp_hostname");
	const char *port     = munit_parameters_get(params, "srp_port");

	(void)srand_reset(params, user_data);

	/* expected to be given from the cli */
	if (exec == NULL)
		return (NULL);
	/* have defaults, see test_srp_py_server_params */
	if (hostname == NULL || port == NULL)
		return (NULL);

	struct py_srp_server_settings *py_server = NULL;
	py_server = munit_malloc(sizeof(struct py_srp_server_settings));
	py_server->pid = fork();
	switch (py_server->pid) {
	case -1: /* error */
		munit_error("fork");
		/* NOTREACHED */
	case 0: /* child process */
		if (freopen("/dev/null", "r", stdin) == NULL)
			munit_error("freopen");
		if (freopen("/dev/null", "w", stdout) == NULL)
			munit_error("freopen");
		if (freopen("/dev/null", "w", stderr) == NULL)
			munit_error("freopen");
		execlp(exec, /* argv[0] */exec,
			    "--hostname", hostname,
			    "--port",     port,
			    "--id",       srp_email,
			    "--password", srp_password,
			    NULL);
		/* if we reach here, execlp(3) has failed */
		munit_error("execlp");
		/* NOTREACHED */
	default: /* parent process */
		/* "yield" the CPU so that our child get a chance to run and
		   start listening */
		sleep(1);
		return (py_server);
	}
}


/*
 * If the py_server was started by py_srp_server_setup(), kill it and free the
 * associated resources.
 *
 * FIXME: kinda duplicated from test_break_mac.c
 */
void
py_srp_server_tear_down(void *data)
{
	struct py_srp_server_settings *py_server = data;

	if (py_server == NULL)
		return;

	if (kill(py_server->pid, SIGTERM) == 0) {
		if (waitpid(py_server->pid, NULL, 0) != py_server->pid)
			munit_error("waitpid");
	}
	free(py_server);
}


static MunitResult
test_srp_parameters(const MunitParameter *params, void *data)
{
	struct bignum *expected_N = bignum_from_hex(nist_p_hex);
	struct bignum *expected_g = bignum_from_hex(nist_g_hex);
	struct bignum *expected_k = bignum_from_hex("3");
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
test_srp_local_server_new(const MunitParameter *params, void *data)
{
	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(srp_password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	struct srp_server *server = srp_local_server_new(I, P);
	munit_assert_not_null(server);
	munit_assert_not_null(server->opaque);
	const struct srp_local_server_opaque *srvinfo = server->opaque;
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
test_srp_client_new(const MunitParameter *params, void *data)
{
	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(srp_password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	struct srp_client *client = srp_client_new(I, P);
	munit_assert_not_null(client);
	munit_assert_not_null(client->opaque);
	const struct srp_client_opaque *clientinfo = client->opaque;
	munit_assert_int(bytes_bcmp(I, clientinfo->I), ==, 0);
	munit_assert_int(bytes_bcmp(P, clientinfo->P), ==, 0);
	munit_assert_null(client->key);

	client->free(client);
	bytes_free(P);
	bytes_free(I);
	return (MUNIT_OK);
}


/* Set 5 / Challenge 36 */
static MunitResult
test_local_srp_auth(const MunitParameter *params, void *data)
{
	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(srp_password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	struct srp_server *server = srp_local_server_new(I, P);
	if (server == NULL)
		munit_error("srp_local_server_new");

	struct srp_client *client = srp_client_new(I, P);
	if (client == NULL)
		munit_error("srp_client_new");

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
test_local_srp_auth_wrong_password(const MunitParameter *params, void *data)
{
	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(srp_password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	struct srp_server *server = srp_local_server_new(I, P);
	if (server == NULL)
		munit_error("srp_local_server_new");

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

	const struct srp_local_server_opaque *srvinfo = server->opaque;
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
test_local_srp_auth_wrong_email(const MunitParameter *params, void *data)
{
	struct bytes *I = bytes_from_str(srp_email);
	struct bytes *P = bytes_from_str(srp_password);
	if (I == NULL || P == NULL)
		munit_error("bytes_from_str");

	struct srp_server *server = srp_local_server_new(I, P);
	if (server == NULL)
		munit_error("srp_local_server_new");

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

	const struct srp_local_server_opaque *srvinfo = server->opaque;
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


static MunitResult
test_py_srp_auth(const MunitParameter *params, void *data)
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

	struct srp_client *client = srp_client_new(I, P);
	if (client == NULL)
		munit_error("srp_client_new");

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
test_py_srp_auth_wrong_password(const MunitParameter *params, void *data)
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

	client->free(client);
	server->free(server);
	bytes_free(client_P);
	bytes_free(P);
	bytes_free(I);
	return (MUNIT_OK);
}


static MunitResult
test_py_srp_auth_wrong_email(const MunitParameter *params, void *data)
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
	{ "server", test_srp_local_server_new, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "client", test_srp_client_new, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "local/auth",             test_local_srp_auth,                srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "local/wrong-password",   test_local_srp_auth_wrong_password, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "local/wrong-identifier", test_local_srp_auth_wrong_email,    srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = "py/auth",
		.test       = test_py_srp_auth,
		.setup      = py_srp_server_setup,
		.tear_down  = py_srp_server_tear_down,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = test_srp_py_server_params,
	},
	{
		.name       = "py/wrong-password",
		.test       = test_py_srp_auth_wrong_password,
		.setup      = py_srp_server_setup,
		.tear_down  = py_srp_server_tear_down,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = test_srp_py_server_params,
	},
	{
		.name       = "py/wrong-identifier",
		.test       = test_py_srp_auth_wrong_email,
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
