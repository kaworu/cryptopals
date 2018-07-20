/*
 * test_bignum.c
 */
#include "munit.h"
#include "helpers.h"
#include "bignum.h"

#include <stdio.h>


static MunitResult
test_bignum_from_hex_and_dec(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		char *expected;
	} vectors[] = {
		{ .input = "0",     .expected = "0"     },
		/* https://github.com/openssl/openssl/commit/01c09f9fde5793e0b3712d602b02e2aed4908e8d */
		/*{ .input =  "-0",   .expected = "0"     },*/
		{ .input = "1",     .expected = "1"     },
		{ .input = "-1",    .expected = "-1"    },
		{ .input = "F",     .expected = "15"    },
		{ .input = "10",    .expected = "16"    },
		{ .input = "F00",   .expected = "3840"  },
		{ .input = "ABCD",  .expected = "43981" },
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input    = vectors[i].input;
		const char *expected = vectors[i].expected;

		struct bignum *hex = bignum_from_hex(input);
		struct bignum *dec = bignum_from_dec(expected);
		munit_assert_not_null(dec);
		munit_assert_not_null(hex);
		munit_assert_int(bignum_cmp(dec, hex), ==, 0);

		bignum_free(hex);
		bignum_free(dec);
	}

	/* when NULL is given */
	munit_assert_null(bignum_from_hex(NULL));
	munit_assert_null(bignum_from_dec(NULL));
	/* invalid values */
	munit_assert_null(bignum_from_hex("mouhahaha"));
	munit_assert_null(bignum_from_dec("mouhahaha"));

	return (MUNIT_OK);
}


static MunitResult
test_bignum_cmp(const MunitParameter *params, void *data)
{
	char buf[BUFSIZ] = { 0 };
	for (size_t i = 0; i < 100; i++) {
		const uint64_t xi = rand_uint64();
		const uint64_t yi = rand_uint64();
		int ret = snprintf(buf, sizeof(buf), "%ju", (uintmax_t)xi);
		if (ret < 0 || (size_t)ret >= sizeof(buf))
			munit_error("snprintf");
		struct bignum *x = bignum_from_dec(buf);
		ret = snprintf(buf, sizeof(buf), "%ju", (uintmax_t)yi);
		if (ret < 0 || (size_t)ret >= sizeof(buf))
			munit_error("snprintf");
		struct bignum *y = bignum_from_dec(buf);
		if (x == NULL || y == NULL)
			munit_error("bignum_from_dec");

		const int x_wrt_y = (xi == yi ? 0 : (xi > yi ? 1 : -1));
		const int y_wrt_x = -(x_wrt_y);
		munit_assert_int(bignum_cmp(x, y), ==, x_wrt_y);
		munit_assert_int(bignum_cmp(y, x), ==, y_wrt_x);
		munit_assert_int(bignum_cmp(x, x), ==, 0);
		munit_assert_int(bignum_cmp(y, y), ==, 0);

		bignum_free(y);
		bignum_free(x);
	}

	struct bignum *zero = bignum_from_dec("0");
	if (zero == NULL)
		munit_error("bignum_from_dec");
	/* when NULL is given */
	munit_assert_int(bignum_cmp(NULL, zero), ==, INT_MIN);
	munit_assert_int(bignum_cmp(zero, NULL), ==, INT_MIN);
	munit_assert_int(bignum_cmp(NULL, NULL), ==, INT_MIN);
	bignum_free(zero);

	return (MUNIT_OK);
}


static MunitResult
test_bignum_modexp(const MunitParameter *params, void *data)
{
	/* example from https://en.wikipedia.org/wiki/Modular_exponentiation */
	struct bignum *base = bignum_from_dec("4");
	struct bignum *exp  = bignum_from_dec("13");
	struct bignum *mod  = bignum_from_dec("497");
	struct bignum *expected = bignum_from_dec("445");

	struct bignum *result = bignum_modexp(base, exp, mod);
	munit_assert_not_null(result);
	munit_assert_int(bignum_cmp(result, expected), ==, 0);
	bignum_free(result);

	/* when NULL is given */
	munit_assert_null(bignum_modexp(NULL, exp, mod));
	munit_assert_null(bignum_modexp(base, NULL, mod));
	munit_assert_null(bignum_modexp(base, exp, NULL));

	bignum_free(expected);
	bignum_free(mod);
	bignum_free(exp);
	bignum_free(base);
	return (MUNIT_OK);
}


static MunitResult
test_bignum_to_dec(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		char *expected;
	} vectors[] = {
		{ .input = "0",     .expected = "0"     },
		/* https://github.com/openssl/openssl/commit/01c09f9fde5793e0b3712d602b02e2aed4908e8d */
		/*{ .input =  "-0",   .expected = "0"     },*/
		{ .input = "1",     .expected = "1"     },
		{ .input = "-1",    .expected = "-1"    },
		{ .input = "F",     .expected = "15"    },
		{ .input = "10",    .expected = "16"    },
		{ .input = "F00",   .expected = "3840"  },
		{ .input = "ABCD",  .expected = "43981" },
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input    = vectors[i].input;
		const char *expected = vectors[i].expected;
		struct bignum *n = bignum_from_hex(input);
		if (n == NULL)
			munit_error("bignum_from_hex");

		char *res = bignum_to_dec(n);
		munit_assert_not_null(res);
		munit_assert_string_equal(res, expected);

		free(res);
		bignum_free(n);
	}

	/* when NULL is given */
	munit_assert_null(bignum_to_dec(NULL));

	return (MUNIT_OK);
}


static MunitResult
test_bignum_to_hex(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		char *expected;
	} vectors[] = {
		{ .input = "0",     .expected = "0"    },
		/* https://github.com/openssl/openssl/commit/01c09f9fde5793e0b3712d602b02e2aed4908e8d */
		/*{ .input =  "-0",   .expected = "0"    },*/
		{ .input = "1",     .expected = "1"    },
		{ .input = "-1",    .expected = "-1"   },
		{ .input = "15",    .expected = "F"    },
		{ .input = "16",    .expected = "10"   },
		{ .input = "3840",  .expected = "F00"  },
		{ .input = "43981", .expected = "ABCD" },
	};

	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		const char *input    = vectors[i].input;
		const char *expected = vectors[i].expected;
		struct bignum *n = bignum_from_dec(input);
		if (n == NULL)
			munit_error("bignum_from_dec");

		char *res = bignum_to_hex(n);
		munit_assert_not_null(res);
		munit_assert_string_equal(res, expected);

		free(res);
		bignum_free(n);
	}

	/* when NULL is given */
	munit_assert_null(bignum_to_hex(NULL));

	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_bignum_suite_tests[] = {
	{ "bignum_from_hex",  test_bignum_from_hex_and_dec, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_from_dec",  test_bignum_from_hex_and_dec, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_cmp",       test_bignum_cmp,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_modexp",    test_bignum_modexp,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_to_dec",    test_bignum_to_dec,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_to_hex",    test_bignum_to_hex,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
