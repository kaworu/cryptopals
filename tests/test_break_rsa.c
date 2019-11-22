/*
 * tests/test_rsa.c
 */
#include "munit.h"
#include "helpers.h"
#include "break_rsa.h"


/* Set 5 / Challenge 40 */
static MunitResult
test_rsa_e3_broadcast_attack(const MunitParameter *params, void *data)
{
	const size_t bitlen = 512;
	struct bytes *plaintext = bytes_from_str("The Magic Words are Squeamish Ossifrage");
	if (plaintext == NULL)
		munit_error("bytes_from_str");

	struct rsa_privkey *privk0 = NULL, *privk1 = NULL, *privk2 = NULL;
	struct rsa_pubkey  *pubk0  = NULL, *pubk1  = NULL, *pubk2  = NULL;

	if (rsa_keygen(bitlen, &privk0, &pubk0) != 0)
		munit_error("rsa_keygen");
	if (rsa_keygen(bitlen, &privk1, &pubk1) != 0)
		munit_error("rsa_keygen");
	if (rsa_keygen(bitlen, &privk2, &pubk2) != 0)
		munit_error("rsa_keygen");

	struct bytes *c0 = rsa_encrypt(plaintext, pubk0);
	struct bytes *c1 = rsa_encrypt(plaintext, pubk1);
	struct bytes *c2 = rsa_encrypt(plaintext, pubk2);
	if (c0 == NULL || c1 == NULL || c2 == NULL)
		munit_error("rsa_encrypt");

	struct bytes *guess = rsa_e3_broadcast_attack(
		    c0, pubk0, c1, pubk1, c2, pubk2);

	munit_assert_not_null(guess);
	munit_assert_int(bytes_bcmp(plaintext, guess), ==, 0);

	bytes_free(guess);
	bytes_free(c2);
	bytes_free(c1);
	bytes_free(c0);
	rsa_pubkey_free(pubk2);
	rsa_privkey_free(privk2);
	rsa_pubkey_free(pubk1);
	rsa_privkey_free(privk1);
	rsa_pubkey_free(pubk0);
	rsa_privkey_free(privk0);
	bytes_free(plaintext);
	return MUNIT_OK;
}


/* The test suite. */
MunitTest test_break_rsa_suite_tests[] = {
	{ "e=3-broadcast-attack", test_rsa_e3_broadcast_attack, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
