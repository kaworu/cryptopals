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

#include "xor.h"
#include "aes.h"


/*
 * Encrypt or decrypt a given ciphertext encrypted via AES-128 in ECB mode under
 * the provided key. For encryption, decryption give 1, respectively 0 for the
 * `enc' parameter. If `padding' is zero padding is not performed, checked on
 * encryption, respectively decryption.
 *
 * Returns the ciphertext or NULL on error.
 */
static struct bytes	*aes_128_ecb_crypt(const struct bytes *in,
			    const struct bytes *key, int enc, int padding);


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

	/* setup the context cipher padding */
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


struct bytes *
aes_128_encrypt(const struct bytes *input, const struct bytes *key)
{
	struct bytes *output = NULL;

	if (input != NULL && input->len == aes_128_blocksize())
		output = aes_128_ecb_crypt(input, key, 1, 0);

	return (output);
}

struct bytes *
aes_128_decrypt(const struct bytes *input, const struct bytes *key)
{
	struct bytes *output = NULL;

	if (input != NULL && input->len == aes_128_blocksize())
		output = aes_128_ecb_crypt(input, key, 0, 0);

	return (output);
}


size_t
aes_128_keylength(void)
{
	return (16);
}


size_t
aes_128_blocksize(void)
{
	return (16);
}
