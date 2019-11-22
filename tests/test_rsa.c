/*
 * tests/test_rsa.c
 */
#include "munit.h"
#include "helpers.h"
#include "rsa.h"


static MunitResult
test_rsa_genkey(const MunitParameter *params, void *data)
{
	struct rsa_privkey *privk = NULL;
	struct rsa_pubkey  *pubk  = NULL;

	/* when NULL is given */
	int ret = rsa_keygen(256, NULL, NULL);
	munit_assert_int(ret, ==, -1);
	ret = rsa_keygen(256, NULL, &pubk);
	munit_assert_int(ret, ==, -1);
	munit_assert_null(pubk);
	ret = rsa_keygen(256, &privk, NULL);
	munit_assert_int(ret, ==, -1);
	munit_assert_null(privk);

	ret = rsa_keygen(256, &privk, &pubk);
	munit_assert_int(ret, ==, 0);
	munit_assert_not_null(privk);
	munit_assert_not_null(pubk);

	rsa_privkey_free(privk);
	rsa_pubkey_free(pubk);
	return MUNIT_OK;
}


static MunitResult
test_rsa_encrypt(const MunitParameter *params, void *data)
{
	struct rsa_privkey *privk = NULL;
	struct rsa_pubkey  *pubk  = NULL;

	if (rsa_keygen(1024, &privk, &pubk) != 0)
		munit_error("rsa_keygen");

	struct bytes *plaintext  = bytes_from_str("The Magic Words are Squeamish Ossifrage");
	struct bytes *ciphertext = rsa_encrypt(plaintext, pubk);
	munit_assert_not_null(ciphertext);
	struct bytes *decrypted  = rsa_decrypt(ciphertext, privk);
	munit_assert_not_null(decrypted);
	munit_assert_int(bytes_bcmp(plaintext, decrypted), ==, 0);

	bytes_free(decrypted);
	bytes_free(ciphertext);
	bytes_free(plaintext);
	rsa_privkey_free(privk);
	rsa_pubkey_free(pubk);
	return MUNIT_OK;
}


/* The test suite. */
MunitTest test_rsa_suite_tests[] = {
	{ "keygen",     test_rsa_genkey,  srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "encryption", test_rsa_encrypt, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
