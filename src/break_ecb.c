/*
 * break_ecb.c
 *
 * ECB analysis stuff for cryptopals.com challenges.
 */
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "aes.h"
#include "break_ecb.h"


int
ecb_detect(const struct bytes *buf, double *score_p)
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
ecb_cbc_encryption_oracle(const struct bytes *input, int *ecb)
{
	const EVP_CIPHER *cipher = EVP_aes_128_cbc();
	struct bytes *random = NULL, *before = NULL, *after = NULL;
	struct bytes *padded = NULL;
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

	/* leading pad */
	before = bytes_randomized(5 + random->data[0] % 6);
	/* trailing pad */
	after = bytes_randomized(5 + random->data[1] % 6);
	const struct bytes *const parts[] = { before, input, after };
	/* build the padded input */
	padded = bytes_joined_const(parts, sizeof(parts) / sizeof(*parts));

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
ecb_cbc_detect_input(void)
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
ecb_cbc_detect(const struct bytes *buf)
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
	if (ecb_detect(blocks, &score) != 0)
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


struct bytes *
ecb_byte_at_a_time_oracle(
		    const struct bytes *payload,
		    const struct bytes *message,
		    const struct bytes *key)
{
	struct bytes *input = NULL, *output = NULL;
	int success = 0;

	/* sanity checks */
	if (payload == NULL || message == NULL || key == NULL)
		goto cleanup;

	const struct bytes *const parts[] = { payload, message };
	input = bytes_joined_const(parts, sizeof(parts) / sizeof(*parts));

	output = aes_128_ecb_encrypt(input, key);
	if (output == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(input);
	if (!success) {
		bytes_free(output);
		output = NULL;
	}
	return (output);
}


struct bytes *
ecb_byte_at_a_time_breaker(const void *message, const void *key)
{
#define oracle(x)	ecb_byte_at_a_time_oracle((x), message, key)
	const EVP_CIPHER *cipher = EVP_aes_128_ecb();
	const size_t expected_blocksize = EVP_CIPHER_block_size(cipher);
	size_t blocksize = 0, msglen = 0;
	struct bytes *payload = NULL, *ciphertext = NULL;
	struct bytes *attempt = NULL, *recovered = NULL;
	int success = 0;

	/* find the blocksize and the message's length */
	size_t prevsize = 0;
	for (size_t i = 0; i <= expected_blocksize && blocksize == 0; i++) {
		struct bytes *payload, *ciphertext;
		payload = bytes_repeated(i, (uint8_t)'A');
		ciphertext = oracle(payload);
		bytes_free(payload);
		if (ciphertext == NULL)
			goto cleanup;
		if (!prevsize) {
			prevsize = ciphertext->len;
		} else if (prevsize < ciphertext->len) {
			blocksize = ciphertext->len - prevsize;
			/* ciphertext is [m . p . p'] where m is the message,
			   p the payload and p' a full block of padding. */
			msglen = ciphertext->len - i - blocksize;
		}
		bytes_free(ciphertext);
	}
	if (blocksize != expected_blocksize)
		goto cleanup;

	/* detect ECB */
	double score = -1;
	payload = bytes_zeroed(3 * blocksize);
	ciphertext = oracle(payload);
	/* in ECB mode, the three first blocks should be the same */
	struct bytes *head = bytes_slice(ciphertext, 0, 3 * blocksize);
	bytes_free(payload);
	bytes_free(ciphertext);
	const int ret = ecb_detect(head, &score);
	bytes_free(head);
	if (ret != 0 || score != 1.0)
		goto cleanup;

	/* allocate the recovered message, initially filled with 0 */
	recovered = bytes_zeroed(msglen);
	if (recovered == NULL)
		goto cleanup;

	/* count of block needed to hold the full message */
	const size_t nblock = msglen / blocksize + 1;
	/* a buffer holding our attempt at cracking the message bytes */
	attempt = bytes_zeroed(nblock * blocksize);
	if (attempt == NULL)
		goto cleanup;
	/* offset of the last block, the one holding the byte we are guessing */
	const size_t boffset = (nblock - 1) * blocksize;
	/* processing loop, breaking one message byte at a time */
	for (size_t i = 1; i <= msglen; i++) {
		struct bytes *pre, *ct, *iblock;
		/* the index of the byte we are breaking in this iteration in
		   the ciphertext given by the oracle */
		const size_t index = nblock * blocksize - i;
		/* pad the start of the choosen plaintext so that the byte at
		   index is at the very end of the block at boffset */
		pre = bytes_repeated(index, (uint8_t)'A');
		ct = oracle(pre);
		/* retrieve the block holding the byte we are guessing */
		iblock = bytes_slice(ct, boffset, blocksize);
		bytes_free(ct);
		/*
		 * Our guess attempt is of the form [pre . guessed . guess].
		 * Just like for iblock `pre' is leading, `guessed' are the byte
		 * we already know and `guess' is our try for the byte at index.
		 */
		(void)bytes_put(attempt, 0, pre);
		(void)bytes_sput(attempt, index, recovered, 0, i);
		/* try each possible value for the byte until we find a match */
		for (uint16_t byte = 0; byte <= UINT8_MAX; byte++) {
			attempt->data[index + i - 1] = (uint8_t)byte;
			ct = oracle(attempt);
			struct bytes *block = bytes_slice(ct, boffset, blocksize);
			bytes_free(ct);
			const int found = (bytes_bcmp(block, iblock) == 0);
			bytes_free(block);
			if (found) {
				recovered->data[i - 1] = (uint8_t)byte;
				break;
			}
		}
		bytes_free(iblock);
		bytes_free(pre);
	}

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(attempt);
	if (!success) {
		bytes_free(recovered);
		recovered = NULL;
	}
	return (recovered);
#undef oracle
}
