/*
 * test_mt19937.c
 */
#include "munit.h"
#include "mt19937.h"


/* Error conditions */
static MunitResult
test_mt19937_0(const MunitParameter *params, void *data)
{
	int ret;

	ret = mt19937_next_uint32(NULL, NULL);
	munit_assert_int(ret, ==, -1);
	ret = mt19937_seed(NULL, 0);
	munit_assert_int(ret, ==, -1);

	return (MUNIT_OK);
}


/* Set 3 / Challenge 21 */
static MunitResult
test_mt19937_1(const MunitParameter *params, void *data)
{
	/*
	 * First 100 random numbers generated using the reference C
	 * implementation at
	 * http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/CODES/mt19937ar.c
	 */
	const uint32_t seed = 42;
	const uint32_t vectors[100] = {
		1608637542, 3421126067, 4083286876,  787846414, 3143890026,
		3348747335, 2571218620, 2563451924,  670094950, 1914837113,
		 669991378,  429389014,  249467210, 1972458954, 3720198231,
		1433267572, 2581769315,  613608295, 3041148567, 2795544706,
		  88409749,  242285876, 4165731073, 3100961111, 3575313899,
		4031053213,  911989541,    3344769,  780932287, 4261516219,
		 787716372, 2652062880, 1306710475, 2627030329, 2253811733,
		  30349564, 1855189739,   99052376, 1250819632, 2253890010,
		2627888186, 1717389822,  599121577,  200427519, 1254751707,
		4182248123, 1573512143,  999745294, 1958805693,  389151677,
		3372305070, 2655947709,  857592370, 1642661739, 2208620086,
		4222944499, 2544401215, 2004731384,  199502978, 3693415908,
		2609385266, 2921898630,  732395540, 1934879560,  279394470,
		  56972561, 4075432323, 4046725720, 4147358011, 2419304461,
		3472040177, 1655351289, 1308306184,   68574553,  419498548,
		 991681409, 2938758483, 1035196507, 1890440558, 2934594491,
		 524150214, 2619915691, 2126768636, 3578544903,  147697582,
		 744595490, 3905501389, 1679592528, 1111451555,  782698033,
		2845511527, 3244252547, 1338788865, 1826030589, 2233675141,
		 893102645, 2348102761, 2438254339,  793943861,  134489564,
	};

	struct mt19937_generator *gen = mt19937_init(seed);
	munit_assert_not_null(gen);
	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		uint32_t n = 0;
		const uint32_t expected = vectors[i];
		const int ret = mt19937_next_uint32(gen, &n);
		munit_assert_int(ret, ==, 0);
		munit_assert_uint32(n, ==, expected);
	}

	/* test with re-seed */
	const int ret = mt19937_seed(gen, seed);
	munit_assert_int(ret, ==, 0);
	for (size_t i = 0; i < (sizeof(vectors) / sizeof(*vectors)); i++) {
		uint32_t n = 0;
		const uint32_t expected = vectors[i];
		const int ret = mt19937_next_uint32(gen, &n);
		munit_assert_int(ret, ==, 0);
		munit_assert_uint32(n, ==, expected);
	}

	mt19937_free(gen);
	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_mt19937_suite_tests[] = {
	{ "mt19937-0", test_mt19937_0, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "mt19937-1", test_mt19937_1, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
