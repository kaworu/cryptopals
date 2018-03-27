/*
 * aes.c
 *
 * AES stuff for cryptopals.com challenges.
 *
 * Mosty just wrapping the OpenSSL API.
 */
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "aes.h"


/**
 * Encrypt or deecrypt a given ciphertext encrypted via AES-128 in ECB mode
 * under the provided key. For encryption, decryption give 1, respectively 0 for
 * the `enc' parameter.
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


static struct bytes *
aes_128_ecb_crypt(const struct bytes *in, const struct bytes *key, int enc)
{
	EVP_CIPHER_CTX *ctx = NULL;
	struct bytes *out = NULL;
	int success = 0;

	/* sanity checks */
	if (in == NULL || key == NULL)
		goto cleanup;
	if (in->len > INT_MAX || key->len > INT_MAX)
		goto cleanup;
	const int inlen  = (int)in->len;
	const int keylen = (int)key->len;

	/* create the context */
	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		goto cleanup;

	/* setup the context cipher */
	const EVP_CIPHER *cipher = EVP_aes_128_ecb();
	if (EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc) != 1)
		goto cleanup;

	/* setup the context cipher key */
	if (EVP_CIPHER_CTX_set_key_length(ctx, keylen) != 1)
		goto cleanup;
	if (EVP_CipherInit_ex(ctx, NULL, NULL, key->data, NULL, -1) != 1)
		goto cleanup;

	const int blocksize = EVP_CIPHER_block_size(cipher);
	if (blocksize <= 0)
		goto cleanup;
	/* NOTE: add twice the block size needed by enc update and final */
	out = bytes_zeroed(in->len + (size_t)blocksize * 2);
	if (out == NULL)
		goto cleanup;

	int uplen = -1;
	int ret = EVP_CipherUpdate(ctx, out->data, &uplen, in->data, inlen);
	if (ret != 1 || uplen < 0)
		goto cleanup;

	int finlen = -1;
	ret = EVP_CipherFinal_ex(ctx, out->data + uplen, &finlen);
	if (ret != 1 || finlen < 0 || (INT_MAX - uplen) < finlen)
		goto cleanup;
	const size_t outlen = (size_t)(uplen + finlen);

	if (out->len < outlen)
		abort();

	out->len = outlen;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		bytes_free(out);
		out = NULL;
	}
	EVP_CIPHER_CTX_free(ctx);
	/* XXX: we don't provide any clue on what happened on error */
	ERR_remove_state(/* pid will be looked up */0);
	return (out);
}
