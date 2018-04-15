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

#include "xor.h"
#include "aes.h"


/**
 * Encrypt or decrypt a given ciphertext encrypted via AES-128 in ECB mode under
 * the provided key. For encryption, decryption give 1, respectively 0 for the
 * `enc' parameter. If `padding' is zero padding is not performed, checked on
 * encryption, respectively decryption.
 *
 * Returns the ciphertext or NULL on error.
 */
static struct bytes	*aes_128_ecb_crypt(const struct bytes *in,
			    const struct bytes *key, int enc, int padding);


struct bytes *
aes_128_ecb_encrypt(const struct bytes *plaintext, const struct bytes *key)
{
	return (aes_128_ecb_crypt(plaintext, key, /* encrypt */1, /* padding */1));
}


struct bytes *
aes_128_ecb_decrypt(const struct bytes *ciphertext, const struct bytes *key)
{
	return (aes_128_ecb_crypt(ciphertext, key, /* encrypt */0, /* padding */1));
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
aes_128_cbc_decrypt(const struct bytes *ciphertext,
		const struct bytes *key, const struct bytes *iv)
{
	const EVP_CIPHER *cipher = EVP_aes_128_cbc();
	const size_t blocksize = EVP_CIPHER_block_size(cipher);
	struct bytes *plaintext = NULL, *padded = NULL;
	struct bytes **ptblocks = NULL;
	size_t nblocks = 0;
	struct bytes *prevblock = NULL;
	int success = 0;

	/* sanity checks */
	if (ciphertext == NULL || key == NULL || iv == NULL)
		goto cleanup;
	if (ciphertext->len % blocksize != 0)
		goto cleanup;
	if (key->len != (size_t)EVP_CIPHER_key_length(cipher))
		goto cleanup;
	if (iv->len != (size_t)EVP_CIPHER_iv_length(cipher))
		goto cleanup;

	nblocks = ciphertext->len / blocksize;
	ptblocks = calloc(nblocks, sizeof(struct bytes *));
	if (ptblocks == NULL)
		goto cleanup;

	/* main decrypt loop, process each block in order. */
	int err = 0;
	for (size_t i = 0; i < nblocks; i++) {
		struct bytes *ctblock;
		/* get the current ciphertext block */
		ctblock = bytes_slice(ciphertext, i * blocksize, blocksize);
		/* decrypt it, the result is not the plaintext block yet */
		ptblocks[i] = aes_128_ecb_crypt(ctblock, key, 0, 0);
		/* add the previous block (the iv on the first iteration) to
		   the decrypted one to find the plaintext block */
		err |= bytes_xor(ptblocks[i], i == 0 ? iv : prevblock);
		/* save the current ciphertext block for the next iteration */
		bytes_free(prevblock);
		prevblock = ctblock;
	}
	if (err)
		goto cleanup;

	/* remove padding */
	padded = bytes_joined(ptblocks, nblocks);
	if (padded == NULL || padded->len == 0)
		goto cleanup;
	const uint8_t padding = padded->data[padded->len - 1];
	if (padding > padded->len)
		goto cleanup;
	plaintext = bytes_slice(padded, /* offset */0, padded->len - padding);

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(padded);
	bytes_free(prevblock);
	for (size_t i = 0; ptblocks != NULL && i < nblocks; i++)
		bytes_free(ptblocks[i]);
	free(ptblocks);
	if (!success) {
		bytes_free(plaintext);
		plaintext = NULL;
	}
	return (plaintext);
}


static struct bytes *
aes_128_ecb_crypt(const struct bytes *in, const struct bytes *key, int enc,
		    int padding)
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
	if (EVP_CIPHER_CTX_set_padding(ctx, padding) != 1)
		goto cleanup;

	/* NOTE: add twice the block size needed by enc update and final */
	out = bytes_zeroed(in->len + blocksize * 2);
	if (out == NULL)
		goto cleanup;

	/* update */
	int uplen = -1;
	int ret = EVP_CipherUpdate(ctx, out->data, &uplen, in->data, in->len);
	if (ret != 1 || uplen < 0)
		goto cleanup;

	/* finalize */
	int finlen = -1;
	ret = EVP_CipherFinal_ex(ctx, out->data + uplen, &finlen);
	if (ret != 1 || finlen < 0 || (INT_MAX - uplen) < finlen)
		goto cleanup;
	const size_t outlen = uplen + finlen;

	/* set the output buffer length */
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
