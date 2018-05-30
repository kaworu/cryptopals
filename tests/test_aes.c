/*
 * test_aes.c
 */
#include "munit.h"
#include "helpers.h"
#include "aes.h"


static MunitResult
test_aes_128_keylength(const MunitParameter *params, void *data)
{
	const size_t len = aes_128_keylength();

	munit_assert_size(len, ==, 16);
	munit_assert_int(aes_128_keylength == aes_128.keylength, ==, 1);

	return (MUNIT_OK);
}


static MunitResult
test_aes_128_expkeylength(const MunitParameter *params, void *data)
{
	const size_t len = aes_128_expkeylength();

	munit_assert_size(len, ==, 176);
	munit_assert_int(aes_128_expkeylength == aes_128.expkeylength, ==, 1);

	return (MUNIT_OK);
}


static MunitResult
test_aes_128_blocksize(const MunitParameter *params, void *data)
{
	const size_t len = aes_128_blocksize();

	munit_assert_size(len, ==, 16);
	munit_assert_int(aes_128_blocksize == aes_128.blocksize, ==, 1);

	return (MUNIT_OK);
}


/* Error conditions */
static MunitResult
test_aes_128_expand_key_0(const MunitParameter *params, void *data)
{
	struct bytes *short_key = bytes_randomized(aes_128_keylength() - 1);
	struct bytes *long_key  = bytes_randomized(aes_128_keylength() + 1);
	struct bytes *empty     = bytes_randomized(0);
	if (short_key == NULL || long_key == NULL || empty == NULL)
		munit_error("bytes_randomized");

	/* when NULL is given */
	munit_assert_null(aes_128_expand_key(NULL));
	/* when the key length is wrong */
	munit_assert_null(aes_128_expand_key(empty));
	munit_assert_null(aes_128_expand_key(short_key));
	munit_assert_null(aes_128_expand_key(long_key));

	munit_assert_int(aes_128_expand_key == aes_128.expand_key, ==, 1);

	bytes_free(empty);
	bytes_free(long_key);
	bytes_free(short_key);
	return (MUNIT_OK);
}


static MunitResult
test_aes_128_expand_key_1(const MunitParameter *params, void *data)
{
	/*
	 * see Appendix A.1 of
	 * https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
	 */
	struct bytes *key = bytes_from_hex("2b7e151628aed2a6abf7158809cf4f3c");
	struct bytes *expected = bytes_from_hex(
			"2b7e151628aed2a6abf7158809cf4f3c"
			"a0fafe1788542cb123a339392a6c7605"
			"f2c295f27a96b9435935807a7359f67f"
			"3d80477d4716fe3e1e237e446d7a883b"
			"ef44a541a8525b7fb671253bdb0bad00"
			"d4d1c6f87c839d87caf2b8bc11f915bc"
			"6d88a37a110b3efddbf98641ca0093fd"
			"4e54f70e5f5fc9f384a64fb24ea6dc4f"
			"ead27321b58dbad2312bf5607f8d292f"
			"ac7766f319fadc2128d12941575c006e"
			"d014f9a8c9ee2589e13f0cc8b6630ca6");
	if (key == NULL || expected == NULL)
		munit_error("bytes_from_hex");

	struct bytes *expanded = aes_128_expand_key(key);
	munit_assert_not_null(expanded);
	munit_assert_size(expanded->len, ==, expected->len);
	munit_assert_memory_equal(expanded->len, expanded->data, expected->data);

	bytes_free(expanded);
	bytes_free(expected);
	bytes_free(key);
	return (MUNIT_OK);
}


/* Error conditions */
static MunitResult
test_aes_128_encrypt_0(const MunitParameter *params, void *data)
{
	struct bytes *short_input  = bytes_randomized(aes_128_blocksize() - 1);
	struct bytes *long_input   = bytes_randomized(aes_128_blocksize() + 1);
	struct bytes *input        = bytes_randomized(aes_128_blocksize());
	struct bytes *short_expkey = bytes_randomized(aes_128_expkeylength() - 1);
	struct bytes *long_expkey  = bytes_randomized(aes_128_expkeylength() + 1);
	struct bytes *expkey       = bytes_randomized(aes_128_expkeylength());
	struct bytes *empty        = bytes_randomized(0);
	if (short_input == NULL || long_input == NULL || input == NULL ||
		    short_expkey == NULL || long_expkey == NULL ||
		    expkey == NULL || empty == NULL) {
		munit_error("bytes_randomized");
	}

	/* when NULL is given */
	munit_assert_null(aes_128_encrypt(NULL,  NULL));
	munit_assert_null(aes_128_encrypt(input, NULL));
	munit_assert_null(aes_128_encrypt(NULL,  expkey));

	/* when the expanded key length is wrong */
	munit_assert_null(aes_128_encrypt(input, empty));
	munit_assert_null(aes_128_encrypt(input, short_expkey));
	munit_assert_null(aes_128_encrypt(input, long_expkey));

	/* when the input length is wrong */
	munit_assert_null(aes_128_encrypt(empty, expkey));
	munit_assert_null(aes_128_encrypt(short_input, expkey));
	munit_assert_null(aes_128_encrypt(long_input, expkey));

	munit_assert_int(aes_128_encrypt == aes_128.encrypt, ==, 1);

	bytes_free(empty);
	bytes_free(expkey);
	bytes_free(long_expkey);
	bytes_free(short_expkey);
	bytes_free(input);
	bytes_free(long_input);
	bytes_free(short_input);
	return (MUNIT_OK);
}


static MunitResult
test_aes_128_encrypt_1(const MunitParameter *params, void *data)
{
	/*
	 * see Appendix C.1 of
	 * https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
	 */
	struct bytes *plaintext = bytes_from_hex("00112233445566778899aabbccddeeff");
	struct bytes *key       = bytes_from_hex("000102030405060708090a0b0c0d0e0f");
	struct bytes *expected  = bytes_from_hex("69c4e0d86a7b0430d8cdb78070b4c55a");

	struct bytes *expkey = aes_128_expand_key(key);
	if (expkey == NULL)
		munit_error("aes_128_expand_key");

	struct bytes *ciphertext = aes_128_encrypt(plaintext, expkey);
	munit_assert_not_null(ciphertext);
	munit_assert_size(ciphertext->len, ==, expected->len);
	munit_assert_memory_equal(ciphertext->len, ciphertext->data, expected->data);

	bytes_free(ciphertext);
	bytes_free(expkey);
	bytes_free(expected);
	bytes_free(key);
	bytes_free(plaintext);

	return (MUNIT_OK);
}


/* Error conditions */
static MunitResult
test_aes_128_decrypt_0(const MunitParameter *params, void *data)
{
	struct bytes *short_input  = bytes_randomized(aes_128_blocksize() - 1);
	struct bytes *long_input   = bytes_randomized(aes_128_blocksize() + 1);
	struct bytes *input        = bytes_randomized(aes_128_blocksize());
	struct bytes *short_expkey = bytes_randomized(aes_128_expkeylength() - 1);
	struct bytes *long_expkey  = bytes_randomized(aes_128_expkeylength() + 1);
	struct bytes *expkey       = bytes_randomized(aes_128_expkeylength());
	struct bytes *empty        = bytes_randomized(0);
	if (short_input == NULL || long_input == NULL || input == NULL ||
		    short_expkey == NULL || long_expkey == NULL ||
		    expkey == NULL || empty == NULL) {
		munit_error("bytes_randomized");
	}

	/* when NULL is given */
	munit_assert_null(aes_128_decrypt(NULL,  NULL));
	munit_assert_null(aes_128_decrypt(input, NULL));
	munit_assert_null(aes_128_decrypt(NULL,  expkey));

	/* when the expanded key length is wrong */
	munit_assert_null(aes_128_decrypt(input, empty));
	munit_assert_null(aes_128_decrypt(input, short_expkey));
	munit_assert_null(aes_128_decrypt(input, long_expkey));

	/* when the input length is wrong */
	munit_assert_null(aes_128_decrypt(empty, expkey));
	munit_assert_null(aes_128_decrypt(short_input, expkey));
	munit_assert_null(aes_128_decrypt(long_input, expkey));

	munit_assert_int(aes_128_decrypt == aes_128.decrypt, ==, 1);

	bytes_free(empty);
	bytes_free(expkey);
	bytes_free(long_expkey);
	bytes_free(short_expkey);
	bytes_free(input);
	bytes_free(long_input);
	bytes_free(short_input);
	return (MUNIT_OK);
}


static MunitResult
test_aes_128_decrypt_1(const MunitParameter *params, void *data)
{
	/*
	 * see Appendix C.1 of
	 * https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
	 */
	struct bytes *ciphertext = bytes_from_hex("69c4e0d86a7b0430d8cdb78070b4c55a");
	struct bytes *key        = bytes_from_hex("000102030405060708090a0b0c0d0e0f");
	struct bytes *expected   = bytes_from_hex("00112233445566778899aabbccddeeff");

	struct bytes *expkey = aes_128_expand_key(key);
	if (expkey == NULL)
		munit_error("aes_128_expand_key");

	struct bytes *plaintext = aes_128_decrypt(ciphertext, expkey);
	munit_assert_not_null(plaintext);
	munit_assert_size(plaintext->len, ==, expected->len);
	munit_assert_memory_equal(plaintext->len, plaintext->data, expected->data);

	bytes_free(plaintext);
	bytes_free(expkey);
	bytes_free(expected);
	bytes_free(key);
	bytes_free(ciphertext);

	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_aes_suite_tests[] = {
	{ "aes_128_keylength",    test_aes_128_keylength,    NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_expkeylength", test_aes_128_expkeylength,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_blocksize",    test_aes_128_blocksize,    NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_expand_key-0", test_aes_128_expand_key_0, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_expand_key-1", test_aes_128_expand_key_1, srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_encrypt-0",    test_aes_128_encrypt_0,    srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_encrypt-1",    test_aes_128_encrypt_1,    NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_decrypt-0",    test_aes_128_decrypt_0,    srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_decrypt-1",    test_aes_128_decrypt_1,    NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
