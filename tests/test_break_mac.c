/*
 * test_break_mac.c
 */
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include "munit.h"
#include "helpers.h"

#include "compat.h"
#include "sha1.h"
#include "mac.h"
#include "break_mac.h"


/*
 * Challenge 31 & 32 Python server stuff.
 *
 * We'll fork/exec the server from here (i.e. munit). We store the server
 * process id and the key it used for MAC'ing.
 */
struct py_server_settings {
	pid_t pid;
	struct bytes *key;
};


/* server parameters. py_server_params and filepath_params are expected to be
   given from the cli, the other are "sane" defaults that may be overrided */
static char *py_server_params[]  = { NULL };
static char *filepath_params[]  = { NULL };
static char *hostname_params[]  = { "localhost", NULL };
static char *port_params[]      = { "9000", NULL };
/* A delay of 50 takes like 90 minutes to complete, 5 takes about 9 minutes. The
   default (2) is the minimum that is still working and take about 3 minutes. */
static char *delay_params[] = { "2", NULL };
/* all the server parameters */
static MunitParameterEnum test_timing_leaking_server_params[] = {
	{ "mac_server",   py_server_params },
	{ "mac_filepath", filepath_params },
	{ "mac_hostname", hostname_params },
	{ "mac_port",     port_params },
	{ "mac_delay",    delay_params },
	{ NULL, NULL },
};


/*
 * Create a random key and fork/exec the timing leaking MAC server.
 *
 * Returns NULL if the server could not started, a pointer to a struct
 * server_settings (provided as user_data to the test and tear down function)
 * otherwise.
 */
static void *
py_server_setup(const MunitParameter *params, void *user_data)
{
	const char *exec     = munit_parameters_get(params, "mac_server");
	const char *hostname = munit_parameters_get(params, "mac_hostname");
	const char *port     = munit_parameters_get(params, "mac_port");
	const char *delay    = munit_parameters_get(params, "mac_delay");

	/* expected to be given from the cli */
	if (exec == NULL)
		return (NULL);
	/* have defaults, see test_timing_leaking_server_params */
	if (hostname == NULL || port == NULL || delay == NULL)
		return (NULL);

	struct py_server_settings *py_server = NULL;
	py_server = munit_malloc(sizeof(struct py_server_settings));

	/* NOTE: The recommended length for HMAC keys is the hash function's
	   output length, see RFC 2104 § 3. */
	py_server->key = bytes_randomized(sha1_hashlength());
	if (py_server->key == NULL)
		munit_error("bytes_randomized");
	char *key = bytes_to_hex(py_server->key);
	if (key == NULL)
		munit_error("bytes_to_hex");

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
			    "--delay",    delay,
			    "--key",      key,
			    NULL);
		/* if we reach here, execlp(3) has failed */
		munit_error("execlp");
		/* NOTREACHED */
	default: /* parent process */
		free(key);
		/* "yield" the CPU so that our child get a chance to run and
		   start listening */
		sleep(1);
		return (py_server);
	}
}


/*
 * If the server was started by py_server_setup(), kill it and free the
 * associated resources.
 *
 * FIXME: kinda duplicated in test_srp.c
 */
static void
py_server_tear_down(void *data)
{
	struct py_server_settings *py_server = data;

	if (py_server == NULL)
		return;

	if (kill(py_server->pid, SIGTERM) == 0) {
		if (waitpid(py_server->pid, NULL, 0) != py_server->pid)
			munit_error("waitpid");
	}
	bytes_free(py_server->key);
	free(py_server);
}


/* Set 4 / Challenge 29 */
static MunitResult
test_extend_sha1_mac_keyed_prefix(const MunitParameter *params, void *data)
{
	struct bytes *key = bytes_randomized(munit_rand_int_range(64, 128));
	if (key == NULL)
		munit_error("bytes_randomized");
	struct bytes *msg = bytes_from_str("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon");
	if (msg == NULL)
		munit_error("bytes_from_str");
	struct bytes *mac = sha1_mac_keyed_prefix(key, msg);
	if (mac == NULL)
		munit_error("sha1_mac_keyed_prefix");

	/* verify the message against its MAC */
	int ret = sha1_mac_keyed_prefix_verify(key, msg, mac);
	munit_assert_int(ret, ==, 0);

	/* perform the message extension */
	struct bytes *ext_msg = NULL, *ext_mac = NULL;
	ret = extend_sha1_mac_keyed_prefix(key, msg, mac,
		    &ext_msg, &ext_mac);
	munit_assert_int(ret, ==, 0);
	munit_assert_not_null(ext_msg);
	munit_assert_not_null(ext_mac);

	/* ensure that the extension has injected the admin=true payload */
	struct bytes *admin = bytes_from_str(";admin=true;");
	if (admin == NULL)
		munit_error("bytes_from_str");
	ret = bytes_find(ext_msg, admin, NULL);
	munit_assert_int(ret, ==, 0);

	/* verify the extended message against its forged MAC */
	ret = sha1_mac_keyed_prefix_verify(key, ext_msg, ext_mac);
	munit_assert_int(ret, ==, 0);

	bytes_free(admin);
	bytes_free(ext_mac);
	bytes_free(ext_msg);
	bytes_free(mac);
	bytes_free(msg);
	bytes_free(key);
	return (MUNIT_OK);
}


/* Set 4 / Challenge 30 */
static MunitResult
test_extend_md4_mac_keyed_prefix(const MunitParameter *params, void *data)
{
	struct bytes *key = bytes_randomized(munit_rand_int_range(64, 128));
	if (key == NULL)
		munit_error("bytes_randomized");
	struct bytes *msg = bytes_from_str("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon");
	if (msg == NULL)
		munit_error("bytes_from_str");
	struct bytes *mac = md4_mac_keyed_prefix(key, msg);
	if (mac == NULL)
		munit_error("md4_mac_keyed_prefix");

	/* verify the message against its MAC */
	int ret = md4_mac_keyed_prefix_verify(key, msg, mac);
	munit_assert_int(ret, ==, 0);

	/* perform the message extension */
	struct bytes *ext_msg = NULL, *ext_mac = NULL;
	ret = extend_md4_mac_keyed_prefix(key, msg, mac,
		    &ext_msg, &ext_mac);
	munit_assert_int(ret, ==, 0);
	munit_assert_not_null(ext_msg);
	munit_assert_not_null(ext_mac);

	/* ensure that the extension has injected the admin=true payload */
	struct bytes *admin = bytes_from_str(";admin=true;");
	if (admin == NULL)
		munit_error("bytes_from_str");
	ret = bytes_find(ext_msg, admin, NULL);
	munit_assert_int(ret, ==, 0);

	/* verify the extended message against its forged MAC */
	ret = md4_mac_keyed_prefix_verify(key, ext_msg, ext_mac);
	munit_assert_int(ret, ==, 0);

	bytes_free(admin);
	bytes_free(ext_mac);
	bytes_free(ext_msg);
	bytes_free(mac);
	bytes_free(msg);
	bytes_free(key);
	return (MUNIT_OK);
}


/* Set 4 / Challenge 31 & 32 */
static MunitResult
test_timing_leaking_server(const MunitParameter *params, void *data)
{
	const struct py_server_settings *py_server = data;
	/* skip this test if the server was not started */
	if (py_server == NULL)
		return (MUNIT_SKIP);

	/* ensure that the server child process is up */
	if (waitpid(py_server->pid, NULL, WNOHANG) != 0)
		munit_error("server started but down?");

	/* expected to be given on the cli */
	const char *filepath = munit_parameters_get(params, "mac_filepath");
	if (filepath == NULL)
		return (MUNIT_SKIP);

	const char *hostname = munit_parameters_get(params, "mac_hostname");
	const char *port     = munit_parameters_get(params, "mac_port");
	if (hostname == NULL || port == NULL)
		return (MUNIT_ERROR);

	struct bytes *content = fs_read(filepath);
	if (content == NULL)
		munit_error("fs_read");

	char *query = NULL;
	if (asprintf(&query, "/test?file=%s&signature=%%s", filepath) == -1)
		munit_error("asprintf");

	struct bytes *guess = break_timing_leaking_server(hostname, port, query,
		    sha1_hashlength());

	munit_assert_not_null(guess);
	munit_assert_size(guess->len, ==, sha1_hashlength());

	/* test against our own HMAC-SHA1 implementation */
	struct bytes *expected = hmac_sha1(py_server->key, content);
	if (expected == NULL)
		munit_error("hmac_sha1");
	munit_assert_size(expected->len, ==, guess->len);
	munit_assert_memory_equal(guess->len, expected->data, guess->data);

	bytes_free(expected);
	bytes_free(guess);
	free(query);
	bytes_free(content);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_break_mac_suite_tests[] = {
	{ "sha1_length_extension", test_extend_sha1_mac_keyed_prefix, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "md4_length_extension",  test_extend_md4_mac_keyed_prefix,  srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = "timing_leaking_server",
		.test       = test_timing_leaking_server,
		.setup      = py_server_setup,
		.tear_down  = py_server_tear_down,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = test_timing_leaking_server_params,
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
