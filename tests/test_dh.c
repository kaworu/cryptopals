/*
 * test_dh.c
 */
#include "munit.h"
#include "helpers.h"
#include "dh.h"
#include "test_dh.h"


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

	munit_assert_not_null(alice->key);
	munit_assert_not_null(bob->key);
	munit_assert_int(bytes_bcmp(alice->key, bob->key), ==, 0);

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
	struct bignum *p = bignum_from_hex(nist_p_hex);
	struct bignum *g = bignum_from_hex(nist_g_hex);
	if (p == NULL || g == NULL)
		munit_error("bignum_from_hex");

	struct dh *alice = dh_new();
	struct dh *bob   = dh_new();
	if (alice == NULL || bob == NULL)
		munit_error("dh_new");

	int ret = alice->exchange(alice, bob, p, g);
	munit_assert_int(ret, ==, 0);

	munit_assert_not_null(alice->key);
	munit_assert_not_null(bob->key);
	munit_assert_int(bytes_bcmp(alice->key, bob->key), ==, 0);

	bob->free(bob);
	alice->free(alice);
	bignum_free(g);
	bignum_free(p);
	return (MUNIT_OK);
}

/* Set 5 / Challenge 34 (first part without MITM) */
static MunitResult
test_message(const MunitParameter *params, void *data)
{
	struct bignum *p = bignum_from_hex(nist_p_hex);
	struct bignum *g = bignum_from_hex(nist_g_hex);
	if (p == NULL || g == NULL)
		munit_error("bignum_from_hex");

	struct dh *alice = dh_new();
	struct dh *bob   = dh_new();
	if (alice == NULL || bob == NULL)
		munit_error("dh_new");

	int ret = alice->exchange(alice, bob, p, g);
	if (ret != 0)
		munit_error("dh exchange");

	struct bytes *message = bytes_from_str("All we have to decide is what to do with the time that is given us.");
	if (message == NULL)
		munit_error("bytes_from_str");

	ret = alice->challenge(alice, bob, message);
	munit_assert_int(ret, ==, 0);

	bytes_free(message);
	bob->free(bob);
	alice->free(alice);
	bignum_free(g);
	bignum_free(p);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_dh_suite_tests[] = {
	{ "small",   test_small_dh, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nist",    test_nist_dh,  srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "message", test_message,  srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
