/*
 * test_dh.c
 */
#include "munit.h"
#include "helpers.h"
#include "dh.h"


/* Set 5 / Challenge 33 (first part) */
static MunitResult
test_small_dh(const MunitParameter *params, void *data)
{
	struct bignum *p = bignum_from_dec("37");
	struct bignum *g = bignum_from_dec("5");
	if (p == NULL || g == NULL)
		munit_error("bignum_from_dec");

	struct dh *alice = dh_new();
	struct dh *bob   = dh_new();
	if (alice == NULL || bob == NULL)
		munit_error("dh_new");

	int ret = alice->exchange(alice, bob, p, g);
	munit_assert_int(ret, ==, 0);

	struct bytes *alice_key = alice->key(alice);
	struct bytes *bob_key   = bob->key(bob);
	munit_assert_not_null(alice_key);
	munit_assert_not_null(bob_key);
	munit_assert_int(bytes_bcmp(alice_key, bob_key), ==, 0);

	bytes_free(bob_key);
	bytes_free(alice_key);
	bob->free(bob);
	alice->free(alice);
	bignum_free(g);
	bignum_free(p);
	return (MUNIT_OK);
}


/* Set 5 / Challenge 33 (NIST parameters) */
static MunitResult
test_nist_dh(const MunitParameter *params, void *data)
{
	struct bignum *p = bignum_from_hex(
		"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
		"fffffffffffff");
	struct bignum *g = bignum_from_hex("2");
	if (p == NULL || g == NULL)
		munit_error("bignum_from_hex");

	struct dh *alice = dh_new();
	struct dh *bob   = dh_new();
	if (alice == NULL || bob == NULL)
		munit_error("dh_new");

	int ret = alice->exchange(alice, bob, p, g);
	munit_assert_int(ret, ==, 0);

	struct bytes *alice_key = alice->key(alice);
	struct bytes *bob_key   = bob->key(bob);
	munit_assert_not_null(alice_key);
	munit_assert_not_null(bob_key);
	munit_assert_int(bytes_bcmp(alice_key, bob_key), ==, 0);

	bytes_free(bob_key);
	bytes_free(alice_key);
	bob->free(bob);
	alice->free(alice);
	bignum_free(g);
	bignum_free(p);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_dh_suite_tests[] = {
	{ "small",  test_small_dh, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nist",   test_nist_dh,  srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
