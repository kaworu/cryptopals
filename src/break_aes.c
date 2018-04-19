/*
 * break_aes.c
 *
 * AES analysis stuff for cryptopals.com challenges.
 */
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "aes.h"
#include "break_aes.h"


int
aes_128_ecb_detect(const struct bytes *buf, double *score_p)
{
	const EVP_CIPHER *cipher = EVP_aes_128_ecb();
	const size_t blocksize = EVP_CIPHER_block_size(cipher);
	size_t nmatch = 0;
	int success = 0;

	/* sanity checks */
	if (buf == NULL || score_p == NULL)
		goto cleanup;

	const size_t nblocks = buf->len / blocksize;
	size_t rounds = 0;
	for (size_t i = 0; i < nblocks; i++) {
		for (size_t j = i + 1; j < nblocks; j++) {
			struct bytes *lhs, *rhs;
			rounds += 1;
			lhs = bytes_slice(buf, i * blocksize, blocksize);
			rhs = bytes_slice(buf, j * blocksize, blocksize);
			if (lhs == NULL || rhs == NULL) {
				bytes_free(lhs);
				bytes_free(rhs);
				goto cleanup;
			}
			/* NOTE: we don't need const time comparison here */
			if (bytes_bcmp(lhs, rhs) == 0)
				nmatch += 1;
			bytes_free(lhs);
			bytes_free(rhs);
		}
	}
	*score_p = (double)nmatch / rounds;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	return (success ? 0 : -1);
}


struct bytes *
aes_128_ecb_cbc_encryption_oracle(const struct bytes *input, int *ecb)
{
	const EVP_CIPHER *cipher = EVP_aes_128_cbc();
	struct bytes *random = NULL, *before = NULL, *after = NULL;
	struct bytes *dup = NULL, *padded = NULL;
	struct bytes *key = NULL, *iv = NULL, *output = NULL;
	int success = 0;

	/* sanity check */
	if (input == NULL)
		goto cleanup;

	/* some random bytes we'll be using */
	random = bytes_randomized(3);
	if (random == NULL)
		goto cleanup;

	/* random key generation */
	key = bytes_randomized((size_t)EVP_CIPHER_key_length(cipher));
	/* random IV generation */
	iv = bytes_randomized((size_t)EVP_CIPHER_iv_length(cipher));

	/* build the padded input */
	/* leading pad */
	before = bytes_randomized(5 + random->data[0] % 6);
	/* trailing pad */
	after = bytes_randomized(5 + random->data[1] % 6);
	/* XXX: we need to clone the input data because it is const */
	dup = bytes_dup(input);
	struct bytes *const parts[3] = { before, dup, after };
	padded = bytes_joined(parts, 3);

	/* choose if we're using ECB mode with a 50% probability */
	const int use_ecb_mode = random->data[2] & 0x1;
	if (use_ecb_mode)
		output = aes_128_ecb_encrypt(padded, key);
	else /* use CBC mode */
		output = aes_128_cbc_encrypt(padded, key, iv);
	if (output == NULL)
		goto cleanup;

	if (ecb != NULL)
		*ecb = use_ecb_mode;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(padded);
	bytes_free(dup);
	bytes_free(after);
	bytes_free(before);
	bytes_free(iv);
	bytes_free(key);
	bytes_free(random);
	if (!success) {
		bytes_free(output);
		output = NULL;
	}
	return (output);
}


struct bytes *
aes_128_ecb_cbc_detect_input(void)
{
	const EVP_CIPHER *cipher = EVP_aes_128_ecb();
	const size_t blocksize = EVP_CIPHER_block_size(cipher);

	/*
	 * The oracle will pad with 5 to 10 bytes. Thus, this first and last
	 * blocks are "lost" for analysis. To be safe, we want at least three
	 * equals blocks to detect ECB mode, so let's encrypt four of them
	 * (because the padding will compromise only up to the first block).
	 */
	const size_t len = 4 * blocksize;
	return (bytes_zeroed(len));
}


int
aes_128_ecb_cbc_detect(const struct bytes *buf)
{
	const EVP_CIPHER *cipher = EVP_aes_128_ecb();
	const size_t blocksize = EVP_CIPHER_block_size(cipher);
	struct bytes *blocks = NULL;
	int ecb = -1;
	int success = 0;

	/* sanity checks */
	if (buf == NULL || buf->len < 5 * blocksize)
		goto cleanup;

	/* we need to drop the first block because it has been messed
	   up by the padding */
	blocks = bytes_slice(buf, blocksize, 3 * blocksize);

	double score = -1;
	if (aes_128_ecb_detect(blocks, &score) != 0)
		goto cleanup;

	/*
	 * in ECB mode the three ciphertext blocks should have the sames bytes
	 * (because the plaintext was the sames bytes), thus we should end up
	 * with a perfect score.
	 */
	ecb = (score == 1.0);

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(blocks);
	return (success ? ecb : -1);
}
