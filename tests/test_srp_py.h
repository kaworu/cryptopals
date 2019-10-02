#ifndef TESTS_TEST_SRP_PY_H
#define TESTS_TEST_SRP_PY_H
/*
 * tests/test_srp_py.h
 *
 * Python SRP server stuff.
 */


/*
 * Challenge 37 python server stuff.
 *
 * We'll fork/exec the server from here (i.e. munit). We store the server
 * process id.
 */
struct py_srp_server_settings {
	pid_t pid;
};


/* server parameters. py_srp_server_params is expected to be given from the cli,
   the other are "sane" defaults that may be overrided */
static char *srp_server_params[]   = { NULL };
static char *srp_hostname_params[] = { "localhost", NULL };
static char *srp_port_params[]     = { "9001", NULL };
/* all the server parameters */
static MunitParameterEnum test_srp_py_server_params[] = {
	{ "srp_server",   srp_server_params },
	{ "srp_hostname", srp_hostname_params },
	{ "srp_port",     srp_port_params },
	{ NULL, NULL },
};


/*
 * fork/exec the Python SRP server.
 *
 * Returns NULL if the server could not started, a pointer to a struct
 * py_srp_server_settings (provided as user_data to the test and tear down
 * function) otherwise.
 */
void	*py_srp_server_setup(const MunitParameter *params, void *user_data);

/*
 * If the py_server was started by py_srp_server_setup(), kill it and free the
 * associated resources.
 *
 * FIXME: kinda duplicated from test_break_mac.c
 */
void	 py_srp_server_tear_down(void *data);

#endif /* ndef TESTS_TEST_SRP_PY_H */
