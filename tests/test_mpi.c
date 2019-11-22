/*
 * test_mpi.c
 */
#include "munit.h"
#include "helpers.h"

#include "mpi.h"
#include "compat.h"


/* helper to create a mpi from an int */
static struct mpi *
my_mpi_from_int(int x)
{
	/*
	 * Use decimal printf(3) format so that negative values are handled
	 * correctly.
	 */
	char *buf = NULL;
	struct mpi *num = NULL;
	int success = 0;

	if (asprintf(&buf, "%d", x) == -1)
		goto cleanup;

	num = mpi_from_dec(buf);
	if (num == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	free(buf);
	if (!success) {
		mpi_free(num);
		num = NULL;
	}
	return (num);
}


static MunitResult
test_mpi_zero(const MunitParameter *params, void *data)
{
	struct mpi *zero = mpi_zero();
	struct mpi *hex  = mpi_from_hex("0");
	struct mpi *dec  = mpi_from_dec("0");
	if (hex == NULL)
		munit_error("mpi_from_hex");
	if (dec == NULL)
		munit_error("mpi_from_dec");

	munit_assert_not_null(zero);
	munit_assert_int(mpi_cmp(zero, hex), ==, 0);
	munit_assert_int(mpi_cmp(zero, dec), ==, 0);

	mpi_free(dec);
	mpi_free(hex);
	mpi_free(zero);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_one(const MunitParameter *params, void *data)
{
	struct mpi *one  = mpi_one();
	struct mpi *hex  = mpi_from_hex("1");
	struct mpi *dec  = mpi_from_dec("1");
	if (hex == NULL)
		munit_error("mpi_from_hex");
	if (dec == NULL)
		munit_error("mpi_from_dec");

	munit_assert_not_null(one);
	munit_assert_int(mpi_cmp(one, hex), ==, 0);
	munit_assert_int(mpi_cmp(one, dec), ==, 0);

	mpi_free(dec);
	mpi_free(hex);
	mpi_free(one);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_from_hex_and_dec(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		char *expected;
	} vectors[] = {
		{ .input = "0",     .expected = "0"     },
		{ .input =  "-0",   .expected = "0"     },
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

		struct mpi *hex = mpi_from_hex(input);
		struct mpi *dec = mpi_from_dec(expected);
		munit_assert_not_null(dec);
		munit_assert_not_null(hex);
		munit_assert_int(mpi_cmp(dec, hex), ==, 0);

		mpi_free(dec);
		mpi_free(hex);
	}

	/* when NULL is given */
	munit_assert_null(mpi_from_hex(NULL));
	munit_assert_null(mpi_from_dec(NULL));
	/* invalid values */
	munit_assert_null(mpi_from_hex("mouhahaha"));
	munit_assert_null(mpi_from_dec("mouhahaha"));

	return (MUNIT_OK);
}


static MunitResult
test_mpi_from_bytes_be(const MunitParameter *params, void *data)
{
	for (size_t i = 1; i <= 128; i++) {
		struct bytes *buf = bytes_randomized(i);
		if (buf == NULL)
			munit_error("bytes_randomized");

		/*
		 * prevent the most significant byte to be zero, because it
		 * would be "lost" when converted to a mpi number.
		 */
		buf->data[0] |= 0x1;

		char *hex = bytes_to_hex(buf);
		if (hex == NULL)
			munit_error("bytes_to_hex");
		struct mpi *expected = mpi_from_hex(hex);
		if (expected == NULL)
			munit_error("mpi_from_hex");

		struct mpi *result = mpi_from_bytes_be(buf);
		munit_assert_not_null(result);
		munit_assert_int(mpi_cmp(expected, result), ==, 0);

		mpi_free(result);
		mpi_free(expected);
		free(hex);
		bytes_free(buf);
	}

	/* when NULL is given */
	munit_assert_null(mpi_from_bytes_be(NULL));

	return (MUNIT_OK);
}


static MunitResult
test_mpi_rand_range(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int xi = munit_rand_int_range(INT_MIN, INT_MAX);
		const int yi = munit_rand_int_range(INT_MIN, INT_MAX);
		struct mpi *x = my_mpi_from_int(xi);
		struct mpi *y = my_mpi_from_int(yi);
		if (x == NULL || y == NULL)
			munit_error("my_mpi_from_int");

		const struct mpi *min = (xi < yi ? x : y);
		const struct mpi *max = (xi < yi ? y : x);
		struct mpi *r = mpi_rand_range(min, max);
		munit_assert_not_null(r);
		munit_assert_int(mpi_cmp(min, r), <=, 0);
		munit_assert_int(mpi_cmp(max, r),  >, 0);
		mpi_free(r);
		mpi_free(y);
		mpi_free(x);
	}

	struct mpi *zero = mpi_zero();
	if (zero == NULL)
		munit_error("mpi_zero");
	struct mpi *one = mpi_one();
	if (one == NULL)
		munit_error("mpi_one");
	/* when NULL is given */
	munit_assert_null(mpi_rand_range(NULL, NULL));
	munit_assert_null(mpi_rand_range(zero, NULL));
	munit_assert_null(mpi_rand_range(NULL, one));
	/* when min > max */
	munit_assert_null(mpi_rand_range(one, zero));

	mpi_free(one);
	mpi_free(zero);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_rand_range_from_zero_to(const MunitParameter *params, void *data)
{
	struct mpi *zero = mpi_zero();
	if (zero == NULL)
		munit_error("mpi_zero");

	for (size_t i = 0; i < 128; i++) {
		const int xi = munit_rand_int_range(0, INT_MAX);
		struct mpi *x = my_mpi_from_int(xi);
		if (x == NULL)
			munit_error("my_mpi_from_int");

		struct mpi *r = mpi_rand_range_from_zero_to(x);
		munit_assert_not_null(r);
		munit_assert_int(mpi_cmp(zero, r), <=, 0);
		munit_assert_int(mpi_cmp(x, r),     >, 0);
		mpi_free(r);
		mpi_free(x);
	}

	struct mpi *neg = mpi_from_dec("-1");
	if (neg == NULL)
		munit_error("mpi_from_dec");
	/* when NULL is given */
	munit_assert_null(mpi_rand_range_from_zero_to(NULL));
	munit_assert_null(mpi_rand_range_from_zero_to(neg));

	mpi_free(neg);
	mpi_free(zero);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_rand_range_from_one_to(const MunitParameter *params, void *data)
{
	struct mpi *one = mpi_zero();
	if (one == NULL)
		munit_error("mpi_zero");

	for (size_t i = 0; i < 128; i++) {
		const int xi = munit_rand_int_range(1, INT_MAX);
		struct mpi *x = my_mpi_from_int(xi);
		if (x == NULL)
			munit_error("my_mpi_from_int");

		struct mpi *r = mpi_rand_range_from_one_to(x);
		munit_assert_not_null(r);
		munit_assert_int(mpi_cmp(one, r), <=, 0);
		munit_assert_int(mpi_cmp(x, r),    >, 0);
		mpi_free(r);
		mpi_free(x);
	}

	struct mpi *zero = mpi_zero();
	if (zero == NULL)
		munit_error("mpi_zero");
	/* when NULL is given */
	munit_assert_null(mpi_rand_range_from_one_to(NULL));
	munit_assert_null(mpi_rand_range_from_one_to(zero));

	mpi_free(zero);
	mpi_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_rand_odd_top2(const MunitParameter *params, void *data)
{
	struct mpi *two = mpi_from_hex("2");
	if (two == NULL)
		munit_error("mpi_from_hex");

	for (int bits = 2; bits <= 256; bits++) {
		struct mpi *n   = my_mpi_from_int(bits);
		struct mpi *n_1 = my_mpi_from_int(bits - 1);
		struct mpi *n_2 = my_mpi_from_int(bits - 2);
		if (n == NULL || n_1 == NULL || n_2 == NULL)
			munit_error("my_mpi_from_int");
		struct mpi *max = mpi_exp(two, n);
		struct mpi *two_pow_n_1 = mpi_exp(two, n_1);
		struct mpi *two_pow_n_2 = mpi_exp(two, n_2);
		if (max == NULL || two_pow_n_1 == NULL || two_pow_n_2 == NULL)
			munit_error("mpi_exp");
		struct mpi *min = mpi_add(two_pow_n_1, two_pow_n_2);
		if (min == NULL)
			munit_error("mpi_add");

		struct mpi *r = mpi_rand_odd_top2((size_t)bits);
		munit_assert_not_null(r);
		munit_assert_int(mpi_test_odd(r), ==, 0);
		munit_assert_int(mpi_cmp(min, r), <=, 0);
		munit_assert_int(mpi_cmp(max, r),  >, 0);
		mpi_free(r);
		mpi_free(min);
		mpi_free(two_pow_n_2);
		mpi_free(two_pow_n_1);
		mpi_free(max);
		mpi_free(n_2);
		mpi_free(n_1);
		mpi_free(n);
	}

	/* invalid bits values */
	munit_assert_null(mpi_rand_odd_top2(1));
	munit_assert_null(mpi_rand_odd_top2((size_t)INT_MAX + 1));

	mpi_free(two);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_dup(const MunitParameter *params, void *data)
{
	struct mpi *n = mpi_rand_odd_top2(128);
	if (n == NULL)
		munit_error("mpi_rand_odd_top2");

	struct mpi *cpy = mpi_dup(n);
	munit_assert_not_null(cpy);
	munit_assert_int(mpi_cmp(n, cpy), ==, 0);

	/* when NULL is given */
	munit_assert_null(mpi_dup(NULL));

	mpi_free(cpy);
	mpi_free(n);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_seti(const MunitParameter *params, void *data)
{
	for (int i = 0; i < 128; i++) {
		const int xi = munit_rand_int_range(0, INT_MAX);
		struct mpi *x = my_mpi_from_int(xi);
		if (x == NULL)
			munit_error("my_mpi_from_int");
		struct mpi *r = mpi_zero();
		if (r == NULL)
			munit_error("mpi_zero");

		const int ret = mpi_seti(r, (uint64_t)xi);
		munit_assert_int(ret, ==, 0);
		munit_assert_int(mpi_cmp(r, x), ==, 0);
		mpi_free(r);
		mpi_free(x);
	}

	/* when NULL is given */
	munit_assert_int(mpi_seti(NULL, 42), ==, -1);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_num_bits(const MunitParameter *params, void *data)
{
	for (size_t i = 1; i < 100; i++) {
		const int expected = (int)i * 8;
		struct bytes *buf = bytes_randomized(i);
		if (buf == NULL)
			munit_error("bytes_randomized");
		/*
		 * prevent the most significant bit to be zero, because it would
		 * be "lost" when converted to a mpi number.
		 */
		buf->data[0] |= 0x80;
		struct mpi *n = mpi_from_bytes_be(buf);
		if (n == NULL)
			munit_error("mpi_from_bytes_be");

		const int count = mpi_num_bits(n);
		munit_assert_int(count, ==, expected);

		mpi_free(n);
		bytes_free(buf);
	}

	/* when NULL is given */
	munit_assert_int(mpi_num_bits(NULL), ==, -1);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_sign(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int xi = munit_rand_int_range(INT_MIN, INT_MAX);
		const int sign = xi < 0 ? -1 : (xi > 0 ? 1 : 0);
		struct mpi *x = my_mpi_from_int(xi);
		if (x == NULL)
			munit_error("my_mpi_from_int");
		munit_assert_int(mpi_sign(x), ==, sign);
		mpi_free(x);
	}

	struct mpi *zero = mpi_zero();
	if (zero == NULL)
		munit_error("mpi_zero");
	/* when 0 is given */
	munit_assert_int(mpi_sign(zero), ==, 0);
	/* when NULL is given */
	munit_assert_int(mpi_sign(NULL), ==, 0);

	mpi_free(zero);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_cmp(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int xi = munit_rand_int_range(INT_MIN, INT_MAX);
		const int yi = munit_rand_int_range(INT_MIN, INT_MAX);
		struct mpi *x = my_mpi_from_int(xi);
		struct mpi *y = my_mpi_from_int(yi);
		if (x == NULL || y == NULL)
			munit_error("my_mpi_from_int");

		const int x_cmp_y = (xi == yi ? 0 : (xi > yi ? 1 : -1));
		const int y_cmp_x = -(x_cmp_y);
		munit_assert_int(mpi_cmp(x, y), ==, x_cmp_y);
		munit_assert_int(mpi_cmp(y, x), ==, y_cmp_x);
		munit_assert_int(mpi_cmp(x, x), ==, 0);
		munit_assert_int(mpi_cmp(y, y), ==, 0);

		mpi_free(y);
		mpi_free(x);
	}

	struct mpi *zero = mpi_zero();
	if (zero == NULL)
		munit_error("mpi_zero");
	/* when NULL is given */
	munit_assert_int(mpi_cmp(NULL, zero), ==, INT_MIN);
	munit_assert_int(mpi_cmp(zero, NULL), ==, INT_MIN);
	munit_assert_int(mpi_cmp(NULL, NULL), ==, INT_MIN);
	mpi_free(zero);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_testi(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int xi = munit_rand_int_range(1, INT_MAX - 1);
		struct mpi *x = my_mpi_from_int(xi);
		if (x == NULL)
			munit_error("my_mpi_from_int");

		munit_assert_int(mpi_testi(x, xi),     ==, 0);
		munit_assert_int(mpi_testi(x, xi + 1), ==, 1);
		munit_assert_int(mpi_testi(x, xi - 1), ==, 1);
		mpi_free(x);
	}

	/* when NULL is given */
	munit_assert_int(mpi_testi(NULL, 42), ==, 1);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_test_zero(const MunitParameter *params, void *data)
{
	struct mpi *zero      = mpi_from_dec("0");
	struct mpi *one       = mpi_from_dec("1");
	struct mpi *minus_one = mpi_from_dec("-1");
	if (zero == NULL || one == NULL || minus_one == NULL)
		munit_error("mpi_from_dec");

	munit_assert_int(mpi_test_zero(zero),      ==, 0);
	munit_assert_int(mpi_test_zero(one),       ==, 1);
	munit_assert_int(mpi_test_zero(minus_one), ==, 1);
	/* when NULL is given */
	munit_assert_int(mpi_test_zero(NULL), ==, 1);

	mpi_free(minus_one);
	mpi_free(one);
	mpi_free(zero);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_test_one(const MunitParameter *params, void *data)
{
	struct mpi *zero      = mpi_from_dec("0");
	struct mpi *one       = mpi_from_dec("1");
	struct mpi *minus_one = mpi_from_dec("-1");
	if (zero == NULL || one == NULL || minus_one == NULL)
		munit_error("mpi_from_dec");

	munit_assert_int(mpi_test_one(zero),      ==, 1);
	munit_assert_int(mpi_test_one(one),       ==, 0);
	munit_assert_int(mpi_test_one(minus_one), ==, 1);
	/* when NULL is given */
	munit_assert_int(mpi_test_one(NULL), ==, 1);

	mpi_free(minus_one);
	mpi_free(one);
	mpi_free(zero);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_test_odd(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int xi = munit_rand_int_range(INT_MIN, INT_MAX);
		const int is_odd = xi % 2;
		struct mpi *x = my_mpi_from_int(xi);
		if (x == NULL)
			munit_error("my_mpi_from_int");
		munit_assert_int(mpi_test_odd(x), ==, (is_odd ? 0 : 1));
		mpi_free(x);
	}

	/* when NULL is given */
	munit_assert_int(mpi_test_odd(NULL), ==, 1);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_test_even(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int xi = munit_rand_int_range(INT_MIN, INT_MAX);
		const int is_even = (xi % 2 == 0);
		struct mpi *x = my_mpi_from_int(xi);
		if (x == NULL)
			munit_error("my_mpi_from_int");
		munit_assert_int(mpi_test_even(x), ==, (is_even ? 0 : 1));
		mpi_free(x);
	}

	/* when NULL is given */
	munit_assert_int(mpi_test_odd(NULL), ==, 1);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_test_probably_prime(const MunitParameter *params, void *data)
{
	/*
	 * some primes picked at
	 * https://en.wikipedia.org/wiki/List_of_prime_numbers
	 */
	static const char *primes[] = {
		/* Carole primes */
		"7", "47", "223", "3967", "16127", "1046527", "16769023",
		"1073676287", "68718952447", "274876858367", "4398042316799",
		"1125899839733759", "18014398241046527",
		"1298074214633706835075030044377087",
		/* Chen primes */
		"2", "3", "5", "7", "11", "13", "17", "19", "23", "29", "31",
		"37", "41", "47", "53", "59", "67", "71", "83", "89", "101",
		"107", "109", "113", "127", "131", "137", "139", "149", "157",
		"167", "179", "181", "191", "197", "199", "211", "227", "233",
		"239", "251", "257", "263", "269", "281", "293", "307", "311",
		"317", "337", "347", "353", "359", "379", "389", "401", "409",
		/* Factorial primes */
		"2", "3", "5", "7", "23", "719", "5039", "39916801",
		"479001599", "87178291199", "10888869450418352160768000001",
		"265252859812191058636308479999999",
		"263130836933693530167218012159999999",
		"8683317618811886495518194401279999999",
		/* Fermat primes */
		"3", "5", "17", "257", "65537",
		/* Kynea primes */
		"2", "7", "23", "79", "1087", "66047", "263167", "16785407",
		"1073807359", "17180131327", "68720001023", "4398050705407",
		"70368760954879", "18014398777917439", "18446744082299486207",
		/* Lucas primes */
		"2", "3", "7", "11", "29", "47", "199", "521", "2207", "3571",
		"9349", "3010349", "54018521", "370248451", "6643838879",
		"119218851371", "5600748293801", "688846502588399",
		"32361122672259149",
		/* Mersenne primes */
		"3", "7", "31", "127", "8191", "131071", "524287", "2147483647",
		"2305843009213693951", "618970019642690137449562111",
		"162259276829213363391578010288127",
		"170141183460469231731687303715884105727",
	};
	static const size_t primeslen = (sizeof(primes) / sizeof(*primes));

	/* test each primes */
	for (size_t i = 0; i < primeslen; i++) {
		struct mpi *x = mpi_from_dec(primes[i]);
		if (x == NULL)
			munit_error("mpi_from_dec");
		munit_assert_int(mpi_test_probably_prime(x), ==, 0);
		mpi_free(x);
	}

	/* non-prime numbers (p * q) where p and q are picked from primes */
	for (size_t i = 0; i < 128; i++) {
		const size_t j = munit_rand_int_range(0, primeslen - 1);
		const size_t k = munit_rand_int_range(0, primeslen - 1);
		struct mpi *p = mpi_from_dec(primes[j]);
		struct mpi *q = mpi_from_dec(primes[k]);
		if (p == NULL || q == NULL)
			munit_error("mpi_from_dec");
		struct mpi *n = mpi_mul(p, q);
		if (n == NULL)
			munit_error("mpi_mul");
		munit_assert_int(mpi_test_probably_prime(n), ==, 1);
		mpi_free(n);
		mpi_free(q);
		mpi_free(p);
	}

	struct mpi *zero      = mpi_from_dec("0");
	struct mpi *minus_one = mpi_from_dec("-1");
	if (zero == NULL || minus_one == NULL)
		munit_error("mpi_from_dec");
	/* when 0 is given */
	munit_assert_int(mpi_test_probably_prime(zero), ==, -1);
	/* when a negative number is given */
	munit_assert_int(mpi_test_probably_prime(minus_one), ==, -1);
	/* when NULL is given */
	munit_assert_int(mpi_test_probably_prime(NULL), ==, -1);

	mpi_free(minus_one);
	mpi_free(zero);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_mod_mut(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai  = munit_rand_int_range(0, INT_MAX);
		const int mi  = munit_rand_int_range(0, INT_MAX);
		const int ri = ai % mi;
		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *m = my_mpi_from_int(mi);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || m == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		const int ret = mpi_mod_mut(a, m);
		munit_assert_int(ret, ==, 0);
		munit_assert_int(mpi_cmp(a, r), ==, 0);

		mpi_free(r);
		mpi_free(m);
		mpi_free(a);
	}

	struct mpi *one = mpi_one();
	if (one == NULL)
		munit_error("mpi_one");
	struct mpi *zero = mpi_zero();
	if (zero == NULL)
		munit_error("mpi_zero");
	/* when zero is given as mod */
	munit_assert_int(mpi_mod_mut(one, zero), ==, -1);
	/* when NULL is given */
	munit_assert_int(mpi_mod_mut(one, NULL), ==, -1);
	munit_assert_int(mpi_mod_mut(NULL, one), ==, -1);

	mpi_free(zero);
	mpi_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_modi(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai  = munit_rand_int_range(0, INT_MAX);
		const uint64_t mod = (uint64_t)munit_rand_int_range(0, INT_MAX);
		struct mpi *a = my_mpi_from_int(ai);
		if (a == NULL)
			munit_error("my_mpi_from_int");

		const uint64_t rem = (uint64_t)ai % mod;
		const uint64_t result = mpi_modi(a, mod);
		munit_assert_uint64(result, ==, rem);

		mpi_free(a);
	}

	struct mpi *one = mpi_one();
	if (one == NULL)
		munit_error("mpi_one");
	/* when 0 is given as mod */
	munit_assert_uint64(mpi_modi(one, 0), ==, UINT64_MAX);
	/* when NULL is given */
	munit_assert_uint64(mpi_modi(NULL, 42), ==, UINT64_MAX);

	mpi_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_lshifti_mut(const MunitParameter *params, void *data)
{
	struct mpi *two = mpi_from_dec("2");

	for (size_t i = 0; i < 128; i++) {
		const int shift = munit_rand_int_range(0, 1024);
		struct bytes *buf = bytes_randomized(i);
		if (buf == NULL)
			munit_error("bytes_randomized");
		struct mpi *n = mpi_from_bytes_be(buf);
		if (n == NULL)
			munit_error("mpi_from_bytes_be");
		struct mpi *nshift = my_mpi_from_int(shift);
		if (nshift == NULL)
			munit_error("my_mpi_from_int");
		struct mpi *multiplier = mpi_exp(two, nshift);
		if (multiplier == NULL)
			munit_error("mpi_exp");
		struct mpi *expected = mpi_mul(n, multiplier);
		if (expected == NULL)
			munit_error("mpi_mul");

		const int ret = mpi_lshifti_mut(n, shift);
		munit_assert_int(ret, ==, 0);
		munit_assert_int(mpi_cmp(n, expected), ==, 0);

		mpi_free(expected);
		mpi_free(multiplier);
		mpi_free(nshift);
		mpi_free(n);
		bytes_free(buf);
	}

	/* when NULL is given */
	munit_assert_int(mpi_lshifti_mut(NULL, 42), ==, -1);

	mpi_free(two);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_lshift1_mut(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai  = munit_rand_int_range(0, INT_MAX / 2);
		const int ri  = ai << 1;
		struct mpi *a = my_mpi_from_int(ai);
		if (a == NULL)
			munit_error("my_mpi_from_int");

		const int ret = mpi_lshift1_mut(a);
		munit_assert_int(ret, ==, 0);
		munit_assert_int(mpi_testi(a, (uint64_t)ri), ==, 0);
		mpi_free(a);
	}

	/* when NULL is given */
	munit_assert_int(mpi_lshift1_mut(NULL), ==, -1);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_rshifti_mut(const MunitParameter *params, void *data)
{
	struct mpi *two = mpi_from_dec("2");

	for (size_t i = 0; i < 128; i++) {
		const int shift = munit_rand_int_range(0, 1024);
		struct bytes *buf = bytes_randomized(i);
		if (buf == NULL)
			munit_error("bytes_randomized");
		struct mpi *n = mpi_from_bytes_be(buf);
		if (n == NULL)
			munit_error("mpi_from_bytes_be");
		struct mpi *nshift = my_mpi_from_int(shift);
		if (nshift == NULL)
			munit_error("my_mpi_from_int");
		struct mpi *divisor = mpi_exp(two, nshift);
		if (divisor == NULL)
			munit_error("mpi_exp");
		struct mpi *expected = mpi_div(n, divisor);
		if (expected == NULL)
			munit_error("mpi_mul");

		const int ret = mpi_rshifti_mut(n, shift);
		munit_assert_int(ret, ==, 0);
		munit_assert_int(mpi_cmp(n, expected), ==, 0);

		mpi_free(expected);
		mpi_free(divisor);
		mpi_free(nshift);
		mpi_free(n);
		bytes_free(buf);
	}

	/* when NULL is given */
	munit_assert_int(mpi_lshifti_mut(NULL, 42), ==, -1);

	mpi_free(two);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_rshift1_mut(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai  = munit_rand_int_range(0, INT_MAX);
		const int ri  = ai >> 1;
		struct mpi *a = my_mpi_from_int(ai);
		if (a == NULL)
			munit_error("my_mpi_from_int");

		const int ret = mpi_rshift1_mut(a);
		munit_assert_int(ret, ==, 0);
		munit_assert_int(mpi_testi(a, (uint64_t)ri), ==, 0);
		mpi_free(a);
	}

	/* when NULL is given */
	munit_assert_int(mpi_rshift1_mut(NULL), ==, -1);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_add(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int bi = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int ri = ai + bi;

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *b = my_mpi_from_int(bi);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || b == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		struct mpi *result = mpi_add(a, b);
		munit_assert_not_null(result);
		munit_assert_int(mpi_cmp(result, r), ==, 0);

		mpi_free(result);
		mpi_free(r);
		mpi_free(b);
		mpi_free(a);
	}

	struct mpi *one = mpi_one();
	if (one == NULL)
		munit_error("mpi_one");
	/* when NULL is given */
	munit_assert_null(mpi_add(NULL, one));
	munit_assert_null(mpi_add(one, NULL));
	munit_assert_null(mpi_add(NULL, NULL));

	mpi_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_add_mut(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int bi = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int ri = ai + bi;

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *b = my_mpi_from_int(bi);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || b == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		const int ret = mpi_add_mut(a, b);
		munit_assert_int(ret, ==, 0);
		munit_assert_int(mpi_cmp(a, r), ==, 0);

		mpi_free(r);
		mpi_free(b);
		mpi_free(a);
	}

	struct mpi *one = mpi_one();
	if (one == NULL)
		munit_error("mpi_one");
	/* when NULL is given */
	munit_assert_int(mpi_add_mut(NULL, one),  ==, -1);
	munit_assert_int(mpi_add_mut(one, NULL),  ==, -1);
	munit_assert_int(mpi_add_mut(NULL, NULL), ==, -1);

	mpi_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_addi(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int bi = munit_rand_int_range(0, INT_MAX / 2);
		const int ri = ai + bi;

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		struct mpi *result = mpi_addi(a, (uint64_t)bi);
		munit_assert_not_null(result);
		munit_assert_int(mpi_cmp(result, r), ==, 0);

		mpi_free(result);
		mpi_free(r);
		mpi_free(a);
	}

	/* when NULL is given */
	munit_assert_null(mpi_addi(NULL, 42));

	return (MUNIT_OK);
}


static MunitResult
test_mpi_addi_mut(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int bi = munit_rand_int_range(0, INT_MAX / 2);
		const int ri = ai + bi;

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		const int ret = mpi_addi_mut(a, (uint64_t)bi);
		munit_assert_int(ret, ==, 0);
		munit_assert_int(mpi_cmp(a, r), ==, 0);

		mpi_free(r);
		mpi_free(a);
	}

	/* when NULL is given */
	munit_assert_int(mpi_addi_mut(NULL, 42), ==, -1);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_mod_add(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int bi = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int mi = munit_rand_int_range(2, 16);
		int ri = (ai + bi) % mi;
		if (ri < 0)
			ri += mi;

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *b = my_mpi_from_int(bi);
		struct mpi *m = my_mpi_from_int(mi);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || b == NULL || m == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		struct mpi *result = mpi_mod_add(a, b, m);
		munit_assert_not_null(result);
		munit_assert_int(mpi_cmp(result, r), ==, 0);

		mpi_free(result);
		mpi_free(r);
		mpi_free(m);
		mpi_free(b);
		mpi_free(a);
	}

	struct mpi *one = mpi_one();
	if (one == NULL)
		munit_error("mpi_one");
	/* when NULL is given */
	munit_assert_null(mpi_mod_add(NULL, one, one));
	munit_assert_null(mpi_mod_add(one, NULL, one));
	munit_assert_null(mpi_mod_add(one, one, NULL));
	munit_assert_null(mpi_mod_add(NULL, NULL, one));
	munit_assert_null(mpi_mod_add(NULL, one, NULL));
	munit_assert_null(mpi_mod_add(one, NULL, NULL));
	munit_assert_null(mpi_mod_add(NULL, NULL, NULL));

	mpi_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_sub(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int bi = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int ri = ai - bi;

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *b = my_mpi_from_int(bi);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || b == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		struct mpi *result = mpi_sub(a, b);

		munit_assert_not_null(result);
		munit_assert_int(mpi_cmp(result, r), ==, 0);

		mpi_free(result);
		mpi_free(r);
		mpi_free(b);
		mpi_free(a);
	}

	struct mpi *one = mpi_one();
	if (one == NULL)
		munit_error("mpi_one");
	/* when NULL is given */
	munit_assert_null(mpi_sub(one, NULL));
	munit_assert_null(mpi_sub(NULL, one));
	munit_assert_null(mpi_sub(NULL, NULL));

	mpi_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_sub_mut(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int bi = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int ri = ai - bi;

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *b = my_mpi_from_int(bi);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || b == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		const int ret = mpi_sub_mut(a, b);

		munit_assert_int(ret, ==, 0);
		munit_assert_int(mpi_cmp(a, r), ==, 0);

		mpi_free(r);
		mpi_free(b);
		mpi_free(a);
	}

	struct mpi *one = mpi_one();
	if (one == NULL)
		munit_error("mpi_one");
	/* when NULL is given */
	munit_assert_int(mpi_sub_mut(one, NULL),  ==, -1);
	munit_assert_int(mpi_sub_mut(NULL, one),  ==, -1);
	munit_assert_int(mpi_sub_mut(NULL, NULL), ==, -1);

	mpi_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_subi(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int bi = munit_rand_int_range(0, INT_MAX / 2);
		const int ri = ai - bi;

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		struct mpi *result = mpi_subi(a, (uint64_t)bi);

		munit_assert_not_null(result);
		munit_assert_int(mpi_cmp(result, r), ==, 0);

		mpi_free(result);
		mpi_free(r);
		mpi_free(a);
	}

	/* when NULL is given */
	munit_assert_null(mpi_subi(NULL, 42));

	return (MUNIT_OK);
}


static MunitResult
test_mpi_subi_mut(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai = munit_rand_int_range(INT_MIN / 2, INT_MAX / 2);
		const int bi = munit_rand_int_range(0, INT_MAX / 2);
		const int ri = ai - bi;

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		const int ret = mpi_subi_mut(a, (uint64_t)bi);

		munit_assert_int(ret, ==, 0);
		munit_assert_int(mpi_cmp(a, r), ==, 0);

		mpi_free(r);
		mpi_free(a);
	}

	/* when NULL is given */
	munit_assert_int(mpi_subi_mut(NULL, 42), ==, -1);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_mul(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai = munit_rand_int_range(-256, 256);
		const int bi = munit_rand_int_range(-256, 256);
		const int ri = (ai * bi);

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *b = my_mpi_from_int(bi);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || b == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		struct mpi *result = mpi_mul(a, b);
		munit_assert_not_null(result);
		munit_assert_int(mpi_cmp(result, r), ==, 0);

		mpi_free(result);
		mpi_free(r);
		mpi_free(b);
		mpi_free(a);
	}

	struct mpi *one = mpi_one();
	if (one == NULL)
		munit_error("mpi_one");
	/* when NULL is given */
	munit_assert_null(mpi_mul(NULL, one));
	munit_assert_null(mpi_mul(one, NULL));
	munit_assert_null(mpi_mul(NULL, NULL));

	mpi_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_mul_mut(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai = munit_rand_int_range(-256, 256);
		const int bi = munit_rand_int_range(-256, 256);
		const int ri = (ai * bi);

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *b = my_mpi_from_int(bi);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || b == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		const int ret = mpi_mul_mut(a, b);

		munit_assert_int(ret, ==, 0);
		munit_assert_int(mpi_cmp(a, r), ==, 0);

		mpi_free(r);
		mpi_free(b);
		mpi_free(a);
	}

	struct mpi *one = mpi_one();
	if (one == NULL)
		munit_error("mpi_one");
	/* when NULL is given */
	munit_assert_int(mpi_mul_mut(one, NULL),  ==, -1);
	munit_assert_int(mpi_mul_mut(NULL, one),  ==, -1);
	munit_assert_int(mpi_mul_mut(NULL, NULL), ==, -1);

	mpi_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_muli(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai = munit_rand_int_range(-256, 256);
		const int bi = munit_rand_int_range(0, 256);
		const int ri = (ai * bi);

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		struct mpi *result = mpi_muli(a, (uint64_t)bi);
		munit_assert_not_null(result);
		munit_assert_int(mpi_cmp(result, r), ==, 0);

		mpi_free(result);
		mpi_free(r);
		mpi_free(a);
	}

	/* when NULL is given */
	munit_assert_null(mpi_muli(NULL, 1));

	return (MUNIT_OK);
}


static MunitResult
test_mpi_muli_mut(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai = munit_rand_int_range(-256, 256);
		const int bi = munit_rand_int_range(0, 256);
		const int ri = (ai * bi);

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		const int ret = mpi_muli_mut(a, (uint64_t)bi);
		munit_assert_int(ret, ==, 0);
		munit_assert_int(mpi_cmp(a, r), ==, 0);

		mpi_free(r);
		mpi_free(a);
	}

	/* when NULL is given */
	munit_assert_int(mpi_muli_mut(NULL, 1), ==, -1);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_mod_mul(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai = munit_rand_int_range(-256, 256);
		const int bi = munit_rand_int_range(-256, 256);
		const int mi = munit_rand_int_range(2, 16);
		int ri = (ai * bi) % mi;
		if (ri < 0)
			ri += mi;

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *b = my_mpi_from_int(bi);
		struct mpi *m = my_mpi_from_int(mi);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || b == NULL || m == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		struct mpi *result = mpi_mod_mul(a, b, m);
		munit_assert_not_null(result);
		munit_assert_int(mpi_cmp(result, r), ==, 0);

		mpi_free(result);
		mpi_free(r);
		mpi_free(m);
		mpi_free(b);
		mpi_free(a);
	}

	struct mpi *one = mpi_one();
	if (one == NULL)
		munit_error("mpi_one");
	/* when NULL is given */
	munit_assert_null(mpi_mod_mul(NULL, one, one));
	munit_assert_null(mpi_mod_mul(one, NULL, one));
	munit_assert_null(mpi_mod_mul(one, one, NULL));
	munit_assert_null(mpi_mod_mul(NULL, NULL, one));
	munit_assert_null(mpi_mod_mul(NULL, one, NULL));
	munit_assert_null(mpi_mod_mul(one, NULL, NULL));
	munit_assert_null(mpi_mod_mul(NULL, NULL, NULL));

	mpi_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_div(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai = munit_rand_int_range(INT_MIN, INT_MAX);
		const int bi = munit_rand_int_range(1, INT_MAX);
		const int ri = (ai / bi);

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *b = my_mpi_from_int(bi);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || b == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		struct mpi *result = mpi_div(a, b);
		munit_assert_not_null(result);
		munit_assert_int(mpi_cmp(result, r), ==, 0);

		mpi_free(result);
		mpi_free(r);
		mpi_free(b);
		mpi_free(a);
	}

	struct mpi *one = mpi_one();
	if (one == NULL)
		munit_error("mpi_one");
	/* when NULL is given */
	munit_assert_null(mpi_div(NULL, one));
	munit_assert_null(mpi_div(one, NULL));
	munit_assert_null(mpi_div(NULL, NULL));

	mpi_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_div_mut(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai = munit_rand_int_range(INT_MIN, INT_MAX);
		const int bi = munit_rand_int_range(1, INT_MAX);
		const int ri = (ai / bi);

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *b = my_mpi_from_int(bi);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || b == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		const int ret = mpi_div_mut(a, b);

		munit_assert_int(ret, ==, 0);
		munit_assert_int(mpi_cmp(a, r), ==, 0);

		mpi_free(r);
		mpi_free(b);
		mpi_free(a);
	}

	struct mpi *one = mpi_one();
	if (one == NULL)
		munit_error("mpi_one");
	/* when NULL is given */
	munit_assert_int(mpi_div_mut(one, NULL),  ==, -1);
	munit_assert_int(mpi_div_mut(NULL, one),  ==, -1);
	munit_assert_int(mpi_div_mut(NULL, NULL), ==, -1);

	mpi_free(one);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_divi(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai = munit_rand_int_range(INT_MIN, INT_MAX);
		const int bi = munit_rand_int_range(1, INT_MAX);
		const int ri = (ai / bi);

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		struct mpi *result = mpi_divi(a, (uint64_t)bi);
		munit_assert_not_null(result);
		munit_assert_int(mpi_cmp(result, r), ==, 0);

		mpi_free(result);
		mpi_free(r);
		mpi_free(a);
	}

	/* when NULL is given */
	munit_assert_null(mpi_divi(NULL, 1));

	return (MUNIT_OK);
}


static MunitResult
test_mpi_divi_mut(const MunitParameter *params, void *data)
{
	for (size_t i = 0; i < 128; i++) {
		const int ai = munit_rand_int_range(INT_MIN, INT_MAX);
		const int bi = munit_rand_int_range(1, INT_MAX);
		const int ri = (ai / bi);

		struct mpi *a = my_mpi_from_int(ai);
		struct mpi *r = my_mpi_from_int(ri);
		if (a == NULL || r == NULL)
			munit_error("my_mpi_from_int");

		const int ret = mpi_divi_mut(a, (uint64_t)bi);
		munit_assert_int(ret, ==, 0);
		munit_assert_int(mpi_cmp(a, r), ==, 0);

		mpi_free(r);
		mpi_free(a);
	}

	/* when NULL is given */
	munit_assert_int(mpi_divi_mut(NULL, 1), ==, -1);

	return (MUNIT_OK);
}


static MunitResult
test_mpi_exp(const MunitParameter *params, void *data)
{
	/* see https://en.wikipedia.org/wiki/Exponentiation#List_of_whole-number_powers */
	const uint64_t powers[11][11] = {
		 [2] = { 1,  2,   4,    8,    16,     32,      64,      128,       256,        512,        1024 },
		 [3] = { 1,  3,   9,   27,    81,    243,     729,     2187,      6561,      19683,       59049 },
		 [4] = { 1,  4,  16,   64,   256,   1024,    4096,    16384,     65536,     262144,     1048576 },
		 [5] = { 1,  5,  25,  125,   625,   3125,   15625,    78125,    390625,    1953125,     9765625 },
		 [6] = { 1,  6,  36,  216,  1296,   7776,   46656,   279936,   1679616,   10077696,    60466176 },
		 [7] = { 1,  7,  49,  343,  2401,  16807,  117649,   823543,   5764801,   40353607,   282475249 },
		 [8] = { 1,  8,  64,  512,  4096,  32768,  262144,  2097152,  16777216,  134217728,  1073741824 },
		 [9] = { 1,  9,  81,  729,  6561,  59049,  531441,  4782969,  43046721,  387420489,  3486784401 },
		[10] = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000, 10000000000 },
	};

	struct mpi *base = mpi_zero();
	struct mpi *exp  = mpi_zero();
	if (base == NULL || exp == NULL)
	for (int ibase = 2; ibase <= 10; ibase++) {
		if (mpi_seti(base, (uint64_t)ibase) != 0)
			munit_error("mpi_seti");
		for (int iexp = 0; iexp <= 10; iexp++) {
			const uint64_t expected = powers[ibase][iexp];
			if (mpi_seti(exp, (uint64_t)iexp) != 0)
				munit_error("mpi_seti");
			struct mpi *result = mpi_exp(base, exp);
			munit_assert_not_null(result);
			munit_assert_int(mpi_testi(result, expected), ==, 0);
			mpi_free(result);
		}
	}

	/* when NULL is given */
	munit_assert_null(mpi_exp(base, NULL));
	munit_assert_null(mpi_exp(NULL, exp));
	munit_assert_null(mpi_exp(NULL, NULL));

	mpi_free(exp);
	mpi_free(base);
	return MUNIT_OK;
}


static MunitResult
test_mpi_mod_exp(const MunitParameter *params, void *data)
{
	/* example from https://en.wikipedia.org/wiki/Modular_exponentiation */
	struct mpi *base = mpi_from_dec("4");
	struct mpi *exp  = mpi_from_dec("13");
	struct mpi *mod  = mpi_from_dec("497");
	struct mpi *expected = mpi_from_dec("445");

	struct mpi *result = mpi_mod_exp(base, exp, mod);
	munit_assert_not_null(result);
	munit_assert_int(mpi_cmp(result, expected), ==, 0);
	mpi_free(result);

	/* when NULL is given */
	munit_assert_null(mpi_mod_exp(NULL, exp, mod));
	munit_assert_null(mpi_mod_exp(base, NULL, mod));
	munit_assert_null(mpi_mod_exp(base, exp, NULL));

	mpi_free(expected);
	mpi_free(mod);
	mpi_free(exp);
	mpi_free(base);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_sqr(const MunitParameter *params, void *data)
{
	struct mpi *two = mpi_from_hex("2");
	if (two == NULL)
		munit_error("mpi_from_hex");

	for (size_t i = 1; i <= 128; i++) {
		struct bytes *xbuf = bytes_randomized(i);
		if (xbuf == NULL)
			munit_error("bytes_randomized");

		struct mpi *x = mpi_from_bytes_be(xbuf);
		if (x == NULL)
			munit_error("mpi_from_bytes_be");
		struct mpi *expected = mpi_exp(x, two);
		if (expected == NULL)
			munit_error("mpi_exp");

		struct mpi *r = mpi_sqr(x);
		munit_assert_not_null(r);
		munit_assert_int(mpi_cmp(expected, r), ==, 0);

		mpi_free(r);
		mpi_free(expected);
		mpi_free(x);
		bytes_free(xbuf);
	}

	/* when NULL is given */
	munit_assert_null(mpi_sqr(NULL));

	mpi_free(two);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_sqr_mut(const MunitParameter *params, void *data)
{
	struct mpi *two = mpi_from_hex("2");
	if (two == NULL)
		munit_error("mpi_from_hex");

	for (size_t i = 1; i <= 128; i++) {
		struct bytes *xbuf = bytes_randomized(i);
		if (xbuf == NULL)
			munit_error("bytes_randomized");

		struct mpi *x = mpi_from_bytes_be(xbuf);
		if (x == NULL)
			munit_error("mpi_from_bytes_be");
		struct mpi *expected = mpi_exp(x, two);
		if (expected == NULL)
			munit_error("mpi_exp");

		const int ret = mpi_sqr_mut(x);
		munit_assert_int(ret, ==, 0);
		munit_assert_int(mpi_cmp(expected, x), ==, 0);

		mpi_free(expected);
		mpi_free(x);
		bytes_free(xbuf);
	}

	/* when NULL is given */
	munit_assert_int(mpi_sqr_mut(NULL), ==, -1);

	mpi_free(two);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_mod_sqr_mut(const MunitParameter *params, void *data)
{
	struct mpi *two = mpi_from_hex("2");
	if (two == NULL)
		munit_error("mpi_from_hex");

	for (size_t i = 1; i <= 128; i++) {
		struct bytes *xbuf   = bytes_randomized(i);
		struct bytes *modbuf = bytes_randomized(i);
		if (xbuf == NULL || modbuf == NULL)
			munit_error("bytes_randomized");

		struct mpi *x   = mpi_from_bytes_be(xbuf);
		struct mpi *mod = mpi_from_bytes_be(modbuf);
		if (x == NULL || mod == NULL)
			munit_error("mpi_from_bytes_be");
		struct mpi *expected = mpi_mod_exp(x, two, mod);
		if (expected == NULL)
			munit_error("mpi_mod_exp");

		const int ret = mpi_mod_sqr_mut(x, mod);
		munit_assert_int(ret, ==, 0);
		munit_assert_int(mpi_cmp(expected, x), ==, 0);

		mpi_free(expected);
		mpi_free(mod);
		mpi_free(x);
		bytes_free(modbuf);
		bytes_free(xbuf);
	}

	/* when NULL is given */
	munit_assert_int(mpi_mod_sqr_mut(two, NULL),  ==, -1);
	munit_assert_int(mpi_mod_sqr_mut(NULL, two),  ==, -1);
	munit_assert_int(mpi_mod_sqr_mut(NULL, NULL), ==, -1);

	mpi_free(two);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_cbrt(const MunitParameter *params, void *data)
{
	struct mpi *three = mpi_from_hex("3");
	if (three == NULL)
		munit_error("mpi_from_hex");

	for (size_t i = 1; i <= 128; i++) {
		struct bytes *xbuf = bytes_randomized(i);
		if (xbuf == NULL)
			munit_error("bytes_randomized");

		struct mpi *x = mpi_from_bytes_be(xbuf);
		if (x == NULL)
			munit_error("mpi_from_bytes_be");
		struct mpi *pow3 = mpi_exp(x, three);
		if (pow3 == NULL)
			munit_error("mpi_exp");

		struct mpi *r = mpi_cbrt(pow3);
		munit_assert_not_null(r);
		munit_assert_int(mpi_cmp(r, x), ==, 0);

		mpi_free(r);
		mpi_free(pow3);
		mpi_free(x);
		bytes_free(xbuf);
	}

	/* when NULL is given */
	munit_assert_null(mpi_cbrt(NULL));

	mpi_free(three);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_egcd(const MunitParameter *params, void *data)
{
	/* Example from the Handbook of Applied Cryptography §14.62 */
	struct mpi *x = mpi_from_dec("693");
	struct mpi *y = mpi_from_dec("609");
	struct mpi *ev = mpi_from_dec("21");
	struct mpi *ea = mpi_from_dec("-181");
	struct mpi *eb = mpi_from_dec("206");

	if (x == NULL || y == NULL || ev == NULL || ea == NULL || eb == NULL)
		munit_error("mpi_from_dec");

	struct mpi *v = NULL, *a = NULL, *b = NULL;
	const int ret = mpi_egcd(x, y, &a, &b, &v);
	munit_assert_int(ret, ==, 0);
	munit_assert_not_null(v);
	munit_assert_int(mpi_cmp(v, ev), ==, 0);
	munit_assert_not_null(a);
	munit_assert_int(mpi_cmp(a, ea), ==, 0);
	munit_assert_not_null(b);
	munit_assert_int(mpi_cmp(b, eb), ==, 0);

	/* when NULL is given */
	munit_assert_int(mpi_egcd(x,    NULL, NULL, NULL, NULL), ==, -1);
	munit_assert_int(mpi_egcd(NULL,    y, NULL, NULL, NULL), ==, -1);
	munit_assert_int(mpi_egcd(NULL, NULL, NULL, NULL, NULL), ==, -1);

	mpi_free(b);
	mpi_free(a);
	mpi_free(v);
	mpi_free(eb);
	mpi_free(ea);
	mpi_free(ev);
	mpi_free(y);
	mpi_free(x);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_mod_inv(const MunitParameter *params, void *data)
{
	/* Example from the Handbook of Applied Cryptography §14.65 */
	struct mpi *m = mpi_from_dec("383");
	struct mpi *a = mpi_from_dec("271");
	struct mpi *einv = mpi_from_dec("106");
	if (m == NULL || a == NULL || einv == NULL)
		munit_error("mpi_from_dec");

	struct mpi *inv = mpi_mod_inv(a, m);
	munit_assert_not_null(inv);
	munit_assert_int(mpi_cmp(inv, einv), ==, 0);

	/* when a is not invertible modulo m */
	munit_assert_null(mpi_mod_inv(a, a));
	/* when NULL is given */
	munit_assert_null(mpi_mod_inv(a, NULL));
	munit_assert_null(mpi_mod_inv(NULL, m));
	munit_assert_null(mpi_mod_inv(NULL, NULL));

	mpi_free(inv);
	mpi_free(einv);
	mpi_free(a);
	mpi_free(m);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_to_bytes_be(const MunitParameter *params, void *data)
{
	for (size_t i = 1; i < 100; i++) {
		struct bytes *buf = bytes_randomized(i);
		if (buf == NULL)
			munit_error("bytes_randomized");

		/*
		 * prevent the most significant byte to be zero, because it
		 * would be "lost" when converted to a mpi number.
		 */
		buf->data[0] |= 0x1;

		char *hex = bytes_to_hex(buf);
		if (hex == NULL)
			munit_error("bytes_to_hex");
		struct mpi *num = mpi_from_hex(hex);
		if (num == NULL)
			munit_error("mpi_from_hex");
		struct bytes *result = mpi_to_bytes_be(num);

		munit_assert_not_null(result);
		munit_assert_size(result->len, ==, buf->len);
		munit_assert_memory_equal(buf->len, result->data, buf->data);

		bytes_free(result);
		mpi_free(num);
		free(hex);
		bytes_free(buf);
	}

	/* when zero is given */
	struct mpi *z = mpi_zero();
	if (z == NULL)
		munit_error("mpi_zero");
	struct bytes *zbuf = mpi_to_bytes_be(z);
	munit_assert_not_null(zbuf);
	munit_assert_size(zbuf->len, ==, 1);
	munit_assert_uint8(zbuf->data[0], ==, 0x00);

	/* when NULL is given */
	munit_assert_null(mpi_to_dec(NULL));

	bytes_free(zbuf);
	mpi_free(z);
	return (MUNIT_OK);
}


static MunitResult
test_mpi_to_dec(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		char *expected;
	} vectors[] = {
		{ .input = "0",     .expected = "0"     },
		{ .input =  "-0",   .expected = "0"     },
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
		struct mpi *n = mpi_from_hex(input);
		if (n == NULL)
			munit_error("mpi_from_hex");

		char *res = mpi_to_dec(n);
		munit_assert_not_null(res);
		munit_assert_string_equal(res, expected);

		free(res);
		mpi_free(n);
	}

	/* when NULL is given */
	munit_assert_null(mpi_to_dec(NULL));

	return (MUNIT_OK);
}


static MunitResult
test_mpi_to_hex(const MunitParameter *params, void *data)
{
	const struct {
		char *input;
		char *expected;
	} vectors[] = {
		{ .input = "0",     .expected = "0"    },
		{ .input =  "-0",   .expected = "0"    },
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
		struct mpi *n = mpi_from_dec(input);
		if (n == NULL)
			munit_error("mpi_from_dec");

		char *res = mpi_to_hex(n);
		munit_assert_not_null(res);
		munit_assert_string_equal(res, expected);

		free(res);
		mpi_free(n);
	}

	/* when NULL is given */
	munit_assert_null(mpi_to_hex(NULL));

	return (MUNIT_OK);
}


static MunitResult
test_mpi_probable_prime(const MunitParameter *params, void *data)
{
	for (size_t bits = 2; bits <= 1024; bits *= 2) {
		struct mpi *n = mpi_probable_prime(bits);
		munit_assert_not_null(n);
		munit_assert_int(mpi_test_probably_prime(n), ==, 0);
		mpi_free(n);
	}

	/* error cases */
	munit_assert_null(mpi_probable_prime(1));
	munit_assert_null(mpi_probable_prime((size_t)INT_MAX + 1));

	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_mpi_suite_tests[] = {
	{ "mpi_zero",       test_mpi_zero,             NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_one",        test_mpi_one,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_from_hex",   test_mpi_from_hex_and_dec, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_from_bytes", test_mpi_from_bytes_be,    srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_rand_range",              test_mpi_rand_range,              srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_rand_range_from_zero_to", test_mpi_rand_range_from_zero_to, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_rand_range_from_one_to",  test_mpi_rand_range_from_one_to,  srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_rand_odd_top2",           test_mpi_rand_odd_top2,           srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_dup",            test_mpi_dup,            srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_seti",           test_mpi_seti,           srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_probable_prime", test_mpi_probable_prime, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_num_bits",       test_mpi_num_bits,       srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_sign",           test_mpi_sign,           srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_cmp",            test_mpi_cmp,            srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_testi",          test_mpi_testi,          srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_test_zero",      test_mpi_test_zero,      srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_test_one",       test_mpi_test_one,       srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_test_odd",       test_mpi_test_odd,       srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_test_even",      test_mpi_test_even,      srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_test_probably_prime", test_mpi_test_probably_prime, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_mod_mut",     test_mpi_mod_mut,     srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_modi",        test_mpi_modi,        srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_lshifti_mut", test_mpi_lshifti_mut, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_lshift1_mut", test_mpi_lshift1_mut, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_rshifti_mut", test_mpi_rshifti_mut, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_rshift1_mut", test_mpi_rshift1_mut, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_add",         test_mpi_add,         srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_add_mut",     test_mpi_add_mut,     srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_addi",        test_mpi_addi,        srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_addi_mut",    test_mpi_addi_mut,    srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_mod_add",     test_mpi_mod_add,     srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_sub",         test_mpi_sub,         srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_sub_mut",     test_mpi_sub_mut,     srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_subi",        test_mpi_subi,        srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_subi_mut",    test_mpi_subi_mut,    srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_mul",         test_mpi_mul,         srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_mul_mut",     test_mpi_mul_mut,     srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_muli",        test_mpi_muli,        srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_muli_mut",    test_mpi_muli_mut,    srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_mod_mul",     test_mpi_mod_mul,     srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_div",         test_mpi_div,         srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_div_mut",     test_mpi_div_mut,     srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_divi",        test_mpi_divi,        srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_divi_mut",    test_mpi_divi_mut,    srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_exp",         test_mpi_exp,         srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_mod_exp",     test_mpi_mod_exp,     srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_sqr",         test_mpi_sqr,         srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_sqr_mut",     test_mpi_sqr_mut,     srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_mod_sqr_mut", test_mpi_mod_sqr_mut, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_cbrt",        test_mpi_cbrt,        srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_egcd",        test_mpi_egcd,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_mod_inv",     test_mpi_mod_inv,     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_to_dec",      test_mpi_to_dec,      srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_to_hex",      test_mpi_to_hex,      srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mpi_to_bytes",    test_mpi_to_bytes_be, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
