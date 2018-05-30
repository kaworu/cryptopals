/*
 * ecb.c
 *
 * Electronic Codebook mode of operation.
 */
#include "ecb.h"
#include "nope.h"
#include "aes.h"


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
aes_128_ecb_encrypt(const struct bytes *plaintext, const struct bytes *key)
{
	return (ecb_encrypt(&aes_128, plaintext, key));
}


struct bytes *
aes_128_ecb_decrypt(const struct bytes *ciphertext, const struct bytes *key)
{
	return (ecb_decrypt(&aes_128, ciphertext, key));
}


struct bytes *
ecb_encrypt(const struct block_cipher *impl, const struct bytes *plaintext,
		    const struct bytes *key)
{
	struct bytes *expkey = NULL, *padded = NULL, *ciphertext = NULL;
	int success = 0;

	/* sanity checks */
	if (impl == NULL || plaintext == NULL)
		goto cleanup;

	expkey = impl->expand_key(key);
	if (expkey == NULL)
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

	/* main encryption loop, process each block in order. */
	int err = 0;
	for (size_t i = 0; i < nblock; i++) {
		struct bytes *ptblock, *ctblock;
		const size_t offset = i * blocksize;
		/* get the current plaintext block */
		ptblock = bytes_slice(padded, offset, blocksize);
		/* the ciphertext block is the plaintext block encrypted */
		ctblock = impl->encrypt(ptblock, expkey);
		bytes_free(ptblock);
		err |= bytes_put(ciphertext, offset, ctblock);
		bytes_free(ctblock);
	}
	if (err)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(expkey);
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
	struct bytes *expkey = NULL, *plaintext = NULL, *unpadded = NULL;
	int success = 0;

	/* sanity checks */
	if (impl == NULL || ciphertext == NULL)
		goto cleanup;

	expkey = impl->expand_key(key);
	if (expkey == NULL)
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

	/* main decryption loop, process each block in order. */
	int err = 0;
	for (size_t i = 0; i < nblock; i++) {
		struct bytes *ctblock, *ptblock;
		const size_t offset = i * blocksize;
		/* get the current ciphertext block */
		ctblock = bytes_slice(ciphertext, offset, blocksize);
		/* the plaintext block is the decrypted ciphertext block */
		ptblock = impl->decrypt(ctblock, expkey);
		bytes_free(ctblock);
		/* populate the padded plaintext */
		err |= bytes_put(plaintext, offset, ptblock);
		bytes_free(ptblock);
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
	bytes_free(expkey);
	bytes_free(plaintext);
	if (!success) {
		bytes_free(unpadded);
		unpadded = NULL;
	}
	return (unpadded);
}
