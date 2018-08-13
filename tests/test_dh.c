/*
 * test_dh.c
 */
#include "munit.h"
#include "helpers.h"
#include "bignum.h"


/* Set 5 / Challenge 33 (first part) */
static MunitResult
test_small_dh(const MunitParameter *params, void *data)
{
	struct bignum *p = bignum_from_dec("37");
	struct bignum *g = bignum_from_dec("5");
	if (p == NULL || g == NULL)
		munit_error("bignum_from_dec");

	struct bignum *a = bignum_rand(p);
	struct bignum *b = bignum_rand(p);
	if (a == NULL || b == NULL)
		munit_error("bignum_rand");

	struct bignum *A = bignum_modexp(g, a, p);
	struct bignum *B = bignum_modexp(g, b, p);
	if (A == NULL || B == NULL)
		munit_error("bignum_modexp");

	struct bignum *sa = bignum_modexp(B, a, p);
	struct bignum *sb = bignum_modexp(A, b, p);
	if (A == NULL || B == NULL)
		munit_error("bignum_modexp");

	munit_assert_int(bignum_cmp(sa, sb), ==, 0);

	bignum_free(sb);
	bignum_free(sa);
	bignum_free(B);
	bignum_free(A);
	bignum_free(b);
	bignum_free(a);
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

	struct bignum *a = bignum_rand(p);
	struct bignum *b = bignum_rand(p);
	if (a == NULL || b == NULL)
		munit_error("bignum_rand");

	struct bignum *A = bignum_modexp(g, a, p);
	struct bignum *B = bignum_modexp(g, b, p);
	if (A == NULL || B == NULL)
		munit_error("bignum_modexp");

	struct bignum *sa = bignum_modexp(B, a, p);
	struct bignum *sb = bignum_modexp(A, b, p);
	if (A == NULL || B == NULL)
		munit_error("bignum_modexp");

	munit_assert_int(bignum_cmp(sa, sb), ==, 0);

	bignum_free(sb);
	bignum_free(sa);
	bignum_free(B);
	bignum_free(A);
	bignum_free(b);
	bignum_free(a);
	bignum_free(g);
	bignum_free(p);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_dh_suite_tests[] = {
	{ "small",  test_small_dh, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "nist",   test_nist_dh,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
