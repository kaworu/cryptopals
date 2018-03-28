/*
 * aes.c
 *
 * AES stuff for cryptopals.com challenges.
 *
 * Mosty just wrapping the OpenSSL API.
 */
#include <string.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "aes.h"


/**
 * Encrypt or decrypt a given ciphertext encrypted via AES-128 in ECB mode under
 * the provided key. For encryption, decryption give 1, respectively 0 for the
 * `enc' parameter.
 *
 * Returns the ciphertext or NULL on error.
 */
static struct bytes	*aes_128_ecb_crypt(const struct bytes *in,
		    const struct bytes *key, int enc);


struct bytes *
aes_128_ecb_encrypt(const struct bytes *plaintext, const struct bytes *key)
{
	return (aes_128_ecb_crypt(plaintext, key, /* encrypt */1));
}


struct bytes *
aes_128_ecb_decrypt(const struct bytes *ciphertext, const struct bytes *key)
{
	return (aes_128_ecb_crypt(ciphertext, key, /* encrypt */0));
}


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
			if (memcmp(lhs, rhs, blocksize) == 0)
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


static struct bytes *
aes_128_ecb_crypt(const struct bytes *in, const struct bytes *key, int enc)
{
	const EVP_CIPHER *cipher = EVP_aes_128_ecb();
	const size_t blocksize = EVP_CIPHER_block_size(cipher);
	EVP_CIPHER_CTX *ctx = NULL;
	struct bytes *out = NULL;
	int success = 0;

	/* sanity checks */
	if (in == NULL || key == NULL)
		goto cleanup;
	if (in->len > INT_MAX || key->len > INT_MAX)
		goto cleanup;

	/* create the context */
	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		goto cleanup;

	/* setup the context cipher */
	if (EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc) != 1)
		goto cleanup;

	/* setup the context cipher key */
	if (EVP_CIPHER_CTX_set_key_length(ctx, key->len) != 1)
		goto cleanup;
	if (EVP_CipherInit_ex(ctx, NULL, NULL, key->data, NULL, -1) != 1)
		goto cleanup;

	/* NOTE: add twice the block size needed by enc update and final */
	out = bytes_zeroed(in->len + blocksize * 2);
	if (out == NULL)
		goto cleanup;

	int uplen = -1;
	int ret = EVP_CipherUpdate(ctx, out->data, &uplen, in->data, in->len);
	if (ret != 1 || uplen < 0)
		goto cleanup;

	int finlen = -1;
	ret = EVP_CipherFinal_ex(ctx, out->data + uplen, &finlen);
	if (ret != 1 || finlen < 0 || (INT_MAX - uplen) < finlen)
		goto cleanup;
	const size_t outlen = uplen + finlen;

	if (out->len < outlen)
		abort();

	out->len = outlen;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	EVP_CIPHER_CTX_free(ctx);
	/* XXX: we don't provide any clue on what happened on error */
	ERR_remove_state(/* pid will be looked up */0);
	if (!success) {
		bytes_free(out);
		out = NULL;
	}
	return (out);
}
