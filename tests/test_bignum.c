/*
 * test_bignum.c
 */
#include "munit.h"
#include "helpers.h"

#include "bignum.h"
#include "compat.h"


/* helper to create a bignum from an int */
static struct bignum *
my_bignum_from_int(int x)
{
	/*
	 * Use decimal printf(3) format so that negative values are handled
	 * correctly.
	 */
	char *buf = NULL;
	struct bignum *num = NULL;
	int success = 0;

	if (asprintf(&buf, "%d", x) == -1)
		goto cleanup;

	num = bignum_from_dec(buf);
	if (num == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	free(buf);
	if (!success) {
		bignum_free(num);
		num = NULL;
	}
	return (num);
}


static MunitResult
test_bignum_zero(const MunitParameter *params, void *data)
{
	struct bignum *zero = bignum_zero();
	struct bignum *hex  = bignum_from_hex("0");
	struct bignum *dec  = bignum_from_dec("0");
	if (hex == NULL)
		munit_error("bignum_from_hex");
	if (dec == NULL)
		munit_error("bignum_from_dec");

	munit_assert_not_null(zero);
	munit_assert_int(bignum_cmp(zero, hex), ==, 0);
	munit_assert_int(bignum_cmp(zero, dec), ==, 0);

	bignum_free(dec);
	bignum_free(hex);
	bignum_free(zero);

	return (MUNIT_OK);
}


static MunitResult
test_bignum_one(const MunitParameter *params, void *data)
{
	struct bignum *one  = bignum_one();
	struct bignum *hex  = bignum_from_hex("1");
	struct bignum *dec  = bignum_from_dec("1");
	if (hex == NULL)
		munit_error("bignum_from_hex");
	if (dec == NULL)
		munit_error("bignum_from_dec");

	munit_assert_not_null(one);
	munit_assert_int(bignum_cmp(one, hex), ==, 0);
	munit_assert_int(bignum_cmp(one, dec), ==, 0);

	bignum_free(dec);
	bignum_free(hex);
	bignum_free(one);

	return (MUNIT_OK);
}


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

		bignum_free(dec);
		bignum_free(hex);
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
test_bignum_from_bytes_be(const MunitParameter *params, void *data)
{
	for (size_t i = 1; i < 100; i++) {
		struct bytes *buf = bytes_randomized(i);
		if (buf == NULL)
			munit_error("bytes_randomized");

		/*
		 * prevent the most significant byte to be zero, because it
		 * would be "lost" when converted to a bignum number.
		 */
		buf->data[0] |= 0x1;

		char *hex = bytes_to_hex(buf);
		if (hex == NULL)
			munit_error("bytes_to_hex");
		struct bignum *expected = bignum_from_hex(hex);
		if (expected == NULL)
			munit_error("bignum_from_hex");

		struct bignum *result = bignum_from_bytes_be(buf);
		munit_assert_not_null(result);
		munit_assert_int(bignum_cmp(expected, result), ==, 0);

		bignum_free(result);
		bignum_free(expected);
		free(hex);
		bytes_free(buf);
	}

	/* when NULL is given */
	munit_assert_null(bignum_from_bytes_be(NULL));

	return (MUNIT_OK);
}


static MunitResult
test_bignum_dup(const MunitParameter *params, void *data)
{
	struct bignum *limit = bignum_from_dec("9001");
	if (limit == NULL)
		munit_error("bignum_from_dec");

	struct bignum *n = bignum_rand(limit);
	if (n == NULL)
		munit_error("bignum_rand");

	struct bignum *cpy = bignum_dup(n);
	munit_assert_not_null(cpy);
	munit_assert_int(bignum_cmp(n, cpy), ==, 0);

	/* when NULL is given */
	munit_assert_null(bignum_dup(NULL));

	bignum_free(cpy);
	bignum_free(n);
	bignum_free(limit);
	return (MUNIT_OK);
}


static MunitResult
test_bignum_cmp(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 100; i++) {
		const int xi = munit_rand_int_range(INT_MIN, INT_MAX);
		const int yi = munit_rand_int_range(INT_MIN, INT_MAX);
		struct bignum *x = my_bignum_from_int(xi);
		struct bignum *y = my_bignum_from_int(yi);
		if (x == NULL || y == NULL)
			munit_error("my_bignum_from_int");

		const int x_cmp_y = (xi == yi ? 0 : (xi > yi ? 1 : -1));
		const int y_cmp_x = -(x_cmp_y);
		munit_assert_int(bignum_cmp(x, y), ==, x_cmp_y);
		munit_assert_int(bignum_cmp(y, x), ==, y_cmp_x);
		munit_assert_int(bignum_cmp(x, x), ==, 0);
		munit_assert_int(bignum_cmp(y, y), ==, 0);

		bignum_free(y);
		bignum_free(x);
	}

	struct bignum *zero = bignum_zero();
	if (zero == NULL)
		munit_error("bignum_zero");
	/* when NULL is given */
	munit_assert_int(bignum_cmp(NULL, zero), ==, INT_MIN);
	munit_assert_int(bignum_cmp(zero, NULL), ==, INT_MIN);
	munit_assert_int(bignum_cmp(NULL, NULL), ==, INT_MIN);
	bignum_free(zero);

	return (MUNIT_OK);
}


static MunitResult
test_bignum_is_zero(const MunitParameter *params, void *data)
{
	struct bignum *zero      = bignum_from_dec("0");
	struct bignum *one       = bignum_from_dec("1");
	struct bignum *minus_one = bignum_from_dec("-1");
	if (zero == NULL || one == NULL || minus_one == NULL)
		munit_error("bignum_from_dec");

	munit_assert_int(bignum_is_zero(zero),       ==, 0);
	munit_assert_int(bignum_is_zero(one),        ==, 1);
	munit_assert_int(bignum_is_zero(minus_one),  ==, 1);
	/* when NULL is given */
	munit_assert_int(bignum_is_zero(NULL), ==, 1);

	bignum_free(minus_one);
	bignum_free(one);
	bignum_free(zero);

	return (MUNIT_OK);
}


static MunitResult
test_bignum_is_one(const MunitParameter *params, void *data)
{
	struct bignum *zero      = bignum_from_dec("0");
	struct bignum *one       = bignum_from_dec("1");
	struct bignum *minus_one = bignum_from_dec("-1");
	if (zero == NULL || one == NULL || minus_one == NULL)
		munit_error("bignum_from_dec");

	munit_assert_int(bignum_is_one(zero),       ==, 1);
	munit_assert_int(bignum_is_one(one),        ==, 0);
	munit_assert_int(bignum_is_one(minus_one),  ==, 1);
	/* when NULL is given */
	munit_assert_int(bignum_is_one(NULL), ==, 1);

	bignum_free(minus_one);
	bignum_free(one);
	bignum_free(zero);

	return (MUNIT_OK);
}


static MunitResult
test_bignum_add(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 100; i++) {
		const int ai = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int bi = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);

		int ri = (ai + bi);

		struct bignum *a = my_bignum_from_int(ai);
		struct bignum *b = my_bignum_from_int(bi);
		struct bignum *r = my_bignum_from_int(ri);
		if (a == NULL || b == NULL || r == NULL)
			munit_error("my_bignum_from_int");

		struct bignum *result = bignum_add(a, b);
		munit_assert_not_null(result);
		munit_assert_int(bignum_cmp(result, r), ==, 0);

		bignum_free(result);
		bignum_free(r);
		bignum_free(b);
		bignum_free(a);
	}

	struct bignum *one = bignum_one();
	if (one == NULL)
		munit_error("bignum_one");
	/* when NULL is given */
	munit_assert_null(bignum_add(NULL, one));
	munit_assert_null(bignum_add(one, NULL));
	munit_assert_null(bignum_add(NULL, NULL));

	bignum_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_bignum_mod_add(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 100; i++) {
		const int ai = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int bi = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int mi = munit_rand_int_range(2, 16);

		int ri = (ai + bi) % mi;
		if (ri < 0)
			ri += mi;

		struct bignum *a = my_bignum_from_int(ai);
		struct bignum *b = my_bignum_from_int(bi);
		struct bignum *m = my_bignum_from_int(mi);
		struct bignum *r = my_bignum_from_int(ri);
		if (a == NULL || b == NULL || m == NULL || r == NULL)
			munit_error("my_bignum_from_int");

		struct bignum *result = bignum_mod_add(a, b, m);
		munit_assert_not_null(result);
		munit_assert_int(bignum_cmp(result, r), ==, 0);

		bignum_free(result);
		bignum_free(r);
		bignum_free(m);
		bignum_free(b);
		bignum_free(a);
	}

	struct bignum *one = bignum_one();
	if (one == NULL)
		munit_error("bignum_one");
	/* when NULL is given */
	munit_assert_null(bignum_mod_add(NULL, one, one));
	munit_assert_null(bignum_mod_add(one, NULL, one));
	munit_assert_null(bignum_mod_add(one, one, NULL));
	munit_assert_null(bignum_mod_add(NULL, NULL, one));
	munit_assert_null(bignum_mod_add(NULL, one, NULL));
	munit_assert_null(bignum_mod_add(one, NULL, NULL));
	munit_assert_null(bignum_mod_add(NULL, NULL, NULL));

	bignum_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_bignum_sub(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 100; i++) {
		const int ai = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int bi = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int ri = ai - bi;

		struct bignum *a = my_bignum_from_int(ai);
		struct bignum *b = my_bignum_from_int(bi);
		struct bignum *r = my_bignum_from_int(ri);
		if (a == NULL || b == NULL || r == NULL)
			munit_error("my_bignum_from_int");

		struct bignum *result = bignum_sub(a, b);

		munit_assert_not_null(result);
		munit_assert_int(bignum_cmp(result, r), ==, 0);

		bignum_free(result);
		bignum_free(r);
		bignum_free(b);
		bignum_free(a);
	}

	struct bignum *one = bignum_one();
	if (one == NULL)
		munit_error("bignum_one");
	/* when NULL is given */
	munit_assert_null(bignum_sub(one, NULL));
	munit_assert_null(bignum_sub(NULL, one));
	munit_assert_null(bignum_sub(NULL, NULL));

	bignum_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_bignum_sub_one(const MunitParameter *params, void *data)
{
	struct bignum *limit = bignum_from_dec("9001");
	if (limit == NULL)
		munit_error("bignum_from_dec");

	struct bignum *n = bignum_rand(limit);
	if (n == NULL)
		munit_error("bignum_rand");

	struct bignum *one = bignum_one();
	if (one == NULL)
		munit_error("bignum_one");

	struct bignum *n_minus_one = bignum_sub(n, one);
	if (n_minus_one == NULL)
		munit_error("bignum_sub");

	struct bignum *result = bignum_sub_one(n);

	munit_assert_not_null(result);
	munit_assert_int(bignum_cmp(result, n_minus_one), ==, 0);

	/* when NULL is given */
	munit_assert_null(bignum_sub_one(NULL));

	bignum_free(result);
	bignum_free(n_minus_one);
	bignum_free(one);
	bignum_free(n);
	bignum_free(limit);
	return (MUNIT_OK);
}


static MunitResult
test_bignum_mul(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 100; i++) {
		const int ai = munit_rand_int_range(-256, 256);
		const int bi = munit_rand_int_range(-256, 256);

		int ri = (ai * bi);

		struct bignum *a = my_bignum_from_int(ai);
		struct bignum *b = my_bignum_from_int(bi);
		struct bignum *r = my_bignum_from_int(ri);
		if (a == NULL || b == NULL || r == NULL)
			munit_error("my_bignum_from_int");

		struct bignum *result = bignum_mul(a, b);
		munit_assert_not_null(result);
		munit_assert_int(bignum_cmp(result, r), ==, 0);

		bignum_free(result);
		bignum_free(r);
		bignum_free(b);
		bignum_free(a);
	}

	struct bignum *one = bignum_one();
	if (one == NULL)
		munit_error("bignum_one");
	/* when NULL is given */
	munit_assert_null(bignum_mul(NULL, one));
	munit_assert_null(bignum_mul(one, NULL));
	munit_assert_null(bignum_mul(NULL, NULL));

	bignum_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_bignum_mod_mul(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 100; i++) {
		const int ai = munit_rand_int_range(-256, 256);
		const int bi = munit_rand_int_range(-256, 256);
		const int mi = munit_rand_int_range(2, 16);

		int ri = (ai * bi) % mi;
		if (ri < 0)
			ri += mi;

		struct bignum *a = my_bignum_from_int(ai);
		struct bignum *b = my_bignum_from_int(bi);
		struct bignum *m = my_bignum_from_int(mi);
		struct bignum *r = my_bignum_from_int(ri);
		if (a == NULL || b == NULL || m == NULL || r == NULL)
			munit_error("my_bignum_from_int");

		struct bignum *result = bignum_mod_mul(a, b, m);
		munit_assert_not_null(result);
		munit_assert_int(bignum_cmp(result, r), ==, 0);

		bignum_free(result);
		bignum_free(r);
		bignum_free(m);
		bignum_free(b);
		bignum_free(a);
	}

	struct bignum *one = bignum_one();
	if (one == NULL)
		munit_error("bignum_one");
	/* when NULL is given */
	munit_assert_null(bignum_mod_mul(NULL, one, one));
	munit_assert_null(bignum_mod_mul(one, NULL, one));
	munit_assert_null(bignum_mod_mul(one, one, NULL));
	munit_assert_null(bignum_mod_mul(NULL, NULL, one));
	munit_assert_null(bignum_mod_mul(NULL, one, NULL));
	munit_assert_null(bignum_mod_mul(one, NULL, NULL));
	munit_assert_null(bignum_mod_mul(NULL, NULL, NULL));

	bignum_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_bignum_mod_exp(const MunitParameter *params, void *data)
{
	/* example from https://en.wikipedia.org/wiki/Modular_exponentiation */
	struct bignum *base = bignum_from_dec("4");
	struct bignum *exp  = bignum_from_dec("13");
	struct bignum *mod  = bignum_from_dec("497");
	struct bignum *expected = bignum_from_dec("445");

	struct bignum *result = bignum_mod_exp(base, exp, mod);
	munit_assert_not_null(result);
	munit_assert_int(bignum_cmp(result, expected), ==, 0);
	bignum_free(result);

	/* when NULL is given */
	munit_assert_null(bignum_mod_exp(NULL, exp, mod));
	munit_assert_null(bignum_mod_exp(base, NULL, mod));
	munit_assert_null(bignum_mod_exp(base, exp, NULL));

	bignum_free(expected);
	bignum_free(mod);
	bignum_free(exp);
	bignum_free(base);
	return (MUNIT_OK);
}


static MunitResult
test_bignum_to_bytes_be(const MunitParameter *params, void *data)
{
	for (size_t i = 1; i < 100; i++) {
		struct bytes *buf = bytes_randomized(i);
		if (buf == NULL)
			munit_error("bytes_randomized");

		/*
		 * prevent the most significant byte to be zero, because it
		 * would be "lost" when converted to a bignum number.
		 */
		buf->data[0] |= 0x1;

		char *hex = bytes_to_hex(buf);
		if (hex == NULL)
			munit_error("bytes_to_hex");
		struct bignum *num = bignum_from_hex(hex);
		if (num == NULL)
			munit_error("bignum_from_hex");
		struct bytes *result = bignum_to_bytes_be(num);

		munit_assert_not_null(result);
		munit_assert_size(result->len, ==, buf->len);
		munit_assert_memory_equal(buf->len, result->data, buf->data);

		bytes_free(result);
		bignum_free(num);
		free(hex);
		bytes_free(buf);
	}

	/* when zero is given */
	struct bignum *z = bignum_zero();
	if (z == NULL)
		munit_error("bignum_zero");
	struct bytes *zbuf = bignum_to_bytes_be(z);
	munit_assert_not_null(zbuf);
	munit_assert_size(zbuf->len, ==, 1);
	munit_assert_uint8(zbuf->data[0], ==, 0x00);

	/* when NULL is given */
	munit_assert_null(bignum_to_dec(NULL));

	bytes_free(zbuf);
	bignum_free(z);
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


static MunitResult
test_bignum_probable_prime(const MunitParameter *params, void *data)
{
	for (size_t bits = 2; bits <= 1024; bits *= 2) {
		struct bignum *n = bignum_probable_prime(bits);
		munit_assert_not_null(n);
		munit_assert_int(bignum_is_probably_prime(n), ==, 0);
		bignum_free(n);
	}

	/* error cases */
	munit_assert_null(bignum_probable_prime(1));
	munit_assert_null(bignum_probable_prime((size_t)INT_MAX + 1));

	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_bignum_suite_tests[] = {
	{ "bignum_zero",           test_bignum_zero,             NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_one",            test_bignum_one,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_from_hex",       test_bignum_from_hex_and_dec, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_from_dec",       test_bignum_from_hex_and_dec, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_from_bytes",     test_bignum_from_bytes_be,    srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_dup",            test_bignum_dup,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_cmp",            test_bignum_cmp,              srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_is_zero",        test_bignum_is_zero,          NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_is_one",         test_bignum_is_one,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_add",            test_bignum_add,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_mod_add",        test_bignum_mod_add,          NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_sub",            test_bignum_sub,              srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_sub_one",        test_bignum_sub_one,          srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_mul",            test_bignum_mul,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_mod_mul",        test_bignum_mod_mul,          NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_mod_exp",        test_bignum_mod_exp,          NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_to_bytes",       test_bignum_to_bytes_be,      srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_to_dec",         test_bignum_to_dec,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_to_hex",         test_bignum_to_hex,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "bignum_probable_prime", test_bignum_probable_prime,   srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
