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
	return (MUNIT_OK);
}


static MunitResult
test_aes_128_blocksize(const MunitParameter *params, void *data)
{
	const size_t len = aes_128_blocksize();
	munit_assert_size(len, ==, 16);
	return (MUNIT_OK);
}


static MunitResult
test_aes_128_rounds(const MunitParameter *params, void *data)
{
	const size_t n = aes_128_rounds();
	munit_assert_size(n, ==, 10);
	return (MUNIT_OK);
}


static MunitResult
test_aes_128_expand_key(const MunitParameter *params, void *data)
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
	struct bytes *short_input = bytes_randomized(aes_128_blocksize() - 1);
	struct bytes *long_input  = bytes_randomized(aes_128_blocksize() + 1);
	struct bytes *input       = bytes_randomized(aes_128_blocksize());
	struct bytes *short_key   = bytes_randomized(aes_128_keylength() - 1);
	struct bytes *long_key    = bytes_randomized(aes_128_keylength() + 1);
	struct bytes *key         = bytes_randomized(aes_128_keylength());
	struct bytes *empty       = bytes_randomized(0);
	if (short_input == NULL || long_input == NULL || input == NULL ||
		    short_key == NULL || long_key == NULL || key == NULL ||
		    empty == NULL) {
		munit_error("bytes_randomized");
	}

	/* when NULL is given */
	munit_assert_null(aes_128_encrypt(NULL,  NULL));
	munit_assert_null(aes_128_encrypt(input, NULL));
	munit_assert_null(aes_128_encrypt(NULL,  key));

	/* when the key length is wrong */
	munit_assert_null(aes_128_encrypt(input, empty));
	munit_assert_null(aes_128_encrypt(input, short_key));
	munit_assert_null(aes_128_encrypt(input, long_key));

	/* when the input length is wrong */
	munit_assert_null(aes_128_encrypt(empty, key));
	munit_assert_null(aes_128_encrypt(short_input, key));
	munit_assert_null(aes_128_encrypt(long_input, key));

	bytes_free(empty);
	bytes_free(key);
	bytes_free(long_key);
	bytes_free(short_key);
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

	struct bytes *ciphertext = aes_128_encrypt(plaintext, key);
	munit_assert_not_null(ciphertext);
	munit_assert_size(ciphertext->len, ==, expected->len);
	munit_assert_memory_equal(ciphertext->len, ciphertext->data, expected->data);

	bytes_free(ciphertext);
	bytes_free(expected);
	bytes_free(key);
	bytes_free(plaintext);

	return (MUNIT_OK);
}


/* Error conditions */
static MunitResult
test_aes_128_decrypt_0(const MunitParameter *params, void *data)
{
	struct bytes *short_input = bytes_randomized(aes_128_blocksize() - 1);
	struct bytes *long_input  = bytes_randomized(aes_128_blocksize() + 1);
	struct bytes *input       = bytes_randomized(aes_128_blocksize());
	struct bytes *short_key   = bytes_randomized(aes_128_keylength() - 1);
	struct bytes *long_key    = bytes_randomized(aes_128_keylength() + 1);
	struct bytes *key         = bytes_randomized(aes_128_keylength());
	struct bytes *empty       = bytes_randomized(0);
	if (short_input == NULL || long_input == NULL || input == NULL ||
		    short_key == NULL || long_key == NULL || key == NULL ||
		    empty == NULL) {
		munit_error("bytes_randomized");
	}

	/* when NULL is given */
	munit_assert_null(aes_128_decrypt(NULL,  NULL));
	munit_assert_null(aes_128_decrypt(input, NULL));
	munit_assert_null(aes_128_decrypt(NULL,  key));

	/* when the key length is wrong */
	munit_assert_null(aes_128_decrypt(input, empty));
	munit_assert_null(aes_128_decrypt(input, short_key));
	munit_assert_null(aes_128_decrypt(input, long_key));

	/* when the input length is wrong */
	munit_assert_null(aes_128_decrypt(empty, key));
	munit_assert_null(aes_128_decrypt(short_input, key));
	munit_assert_null(aes_128_decrypt(long_input, key));

	bytes_free(empty);
	bytes_free(key);
	bytes_free(long_key);
	bytes_free(short_key);
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

	struct bytes *plaintext = aes_128_decrypt(ciphertext, key);
	munit_assert_not_null(plaintext);
	munit_assert_size(plaintext->len, ==, expected->len);
	munit_assert_memory_equal(plaintext->len, plaintext->data, expected->data);

	bytes_free(plaintext);
	bytes_free(expected);
	bytes_free(key);
	bytes_free(ciphertext);

	return (MUNIT_OK);
}


/* The test suite. */
MunitTest test_aes_suite_tests[] = {
	{ "aes_128_keylength",  test_aes_128_keylength,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_blocksize",  test_aes_128_blocksize,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_rounds",     test_aes_128_rounds,     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_expand_key", test_aes_128_expand_key, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_encrypt-0",  test_aes_128_encrypt_0,  srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_encrypt-1",  test_aes_128_encrypt_1,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_decrypt-0",  test_aes_128_decrypt_0,  srand_reset, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{ "aes_128_decrypt-1",  test_aes_128_decrypt_1,  NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
	{
		.name       = NULL,
		.test       = NULL,
		.setup      = NULL,
		.tear_down  = NULL,
		.options    = MUNIT_TEST_OPTION_NONE,
		.parameters = NULL,
	},
};
