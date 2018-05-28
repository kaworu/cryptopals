/*
 * ecb.c
 *
 * Electronic Codebook mode of operation.
 */
#include "ecb.h"
#include "nope.h"


/*
 * Encrypt the given plaintext under the provided key.
 */
struct bytes	*ecb_encrypt(const struct block_cipher *impl,
		    const struct bytes *plaintext, const struct bytes *key);

/*
 * Decrypt the given ciphertext using the provided key.
 */
struct bytes	*ecb_decrypt(const struct block_cipher *impl,
		    const struct bytes *ciphertext, const struct bytes *key);


struct bytes *
nope_ecb_encrypt(const struct bytes *plaintext, const struct bytes *key)
{
	return (ecb_encrypt(&nope, plaintext, key));
}


struct bytes *
nope_ecb_decrypt(const struct bytes *ciphertext, const struct bytes *key)
{
	return (ecb_decrypt(&nope, ciphertext, key));
}


struct bytes *
ecb_encrypt(const struct block_cipher *impl, const struct bytes *plaintext,
		    const struct bytes *key)
{
	struct bytes *padded = NULL, *ciphertext = NULL;
	int success = 0;

	if (impl == NULL || plaintext == NULL)
		goto cleanup;

	const size_t blocksize = impl->blocksize();
	/* pad the plaintext to the cipher block size */
	padded = bytes_pkcs7_padded(plaintext, blocksize);
	if (padded == NULL)
		goto cleanup;
	/* now we can easily compute the block count */
	const size_t nblock = padded->len / blocksize;
	/* create the ciphertext buffer */
	ciphertext = bytes_zeroed(padded->len);
	if (ciphertext == NULL)
		goto cleanup;

	int err = 0;
	for (size_t i = 0; i < nblock; i++) {
		const size_t offset = i * blocksize;
		struct bytes *ptblock = bytes_slice(padded, offset, blocksize);
		struct bytes *ctblock = impl->encrypt(ptblock, key);
		err |= bytes_put(ciphertext, offset, ctblock);
		bytes_free(ctblock);
		bytes_free(ptblock);
	}
	if (err)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(padded);
	if (!success) {
		bytes_free(ciphertext);
		ciphertext = NULL;
	}
	return (ciphertext);
}


struct bytes *
ecb_decrypt(const struct block_cipher *impl, const struct bytes *ciphertext,
		    const struct bytes *key)
{
	struct bytes *plaintext = NULL, *unpadded = NULL;
	int success = 0;

	if (impl == NULL || ciphertext == NULL)
		goto cleanup;

	const size_t blocksize = impl->blocksize();
	if (ciphertext->len % blocksize != 0)
		goto cleanup;

	/* compute the block count */
	const size_t nblock = ciphertext->len / blocksize;
	/* create the plaintext buffer */
	plaintext = bytes_zeroed(ciphertext->len);
	if (plaintext == NULL)
		goto cleanup;

	int err = 0;
	for (size_t i = 0; i < nblock; i++) {
		const size_t offset = i * blocksize;
		struct bytes *ctblock = bytes_slice(ciphertext, offset, blocksize);
		struct bytes *ptblock = impl->decrypt(ctblock, key);
		err |= bytes_put(plaintext, offset, ptblock);
		bytes_free(ptblock);
		bytes_free(ctblock);
	}
	if (err)
		goto cleanup;

	/* remove the padding from the plaintext */
	unpadded = bytes_pkcs7_unpadded(plaintext);
	if (unpadded == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(plaintext);
	if (!success) {
		bytes_free(unpadded);
		unpadded = NULL;
	}
	return (unpadded);
}
