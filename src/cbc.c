/*
 * cbc.c
 *
 * Cipher Block Chaining mode of operation.
 */
#include "xor.h"
#include "cbc.h"
#include "nope.h"
#include "aes.h"


/*
 * Encrypt the given plaintext under the provided key.
 */
struct bytes	*cbc_encrypt(const struct block_cipher *impl,
		    const struct bytes *plaintext, const struct bytes *key,
		    const struct bytes *iv);

/*
 * Decrypt the given ciphertext using the provided key.
 */
struct bytes	*cbc_decrypt(const struct block_cipher *impl,
		    const struct bytes *ciphertext, const struct bytes *key,
		    const struct bytes *iv);


struct bytes *
nope_cbc_encrypt(const struct bytes *plaintext, const struct bytes *key,
		    const struct bytes *iv)
{
	return (cbc_encrypt(&nope, plaintext, key, iv));
}


struct bytes *
nope_cbc_decrypt(const struct bytes *ciphertext, const struct bytes *key,
		    const struct bytes *iv)
{
	return (cbc_decrypt(&nope, ciphertext, key, iv));
}


struct bytes *
aes_128_cbc_encrypt(const struct bytes *plaintext, const struct bytes *key,
		    const struct bytes *iv)
{
	return (cbc_encrypt(&aes_128, plaintext, key, iv));
}


struct bytes *
aes_128_cbc_decrypt(const struct bytes *ciphertext, const struct bytes *key,
		    const struct bytes *iv)
{
	return (cbc_decrypt(&aes_128, ciphertext, key, iv));
}


struct bytes *
cbc_encrypt(const struct block_cipher *impl, const struct bytes *plaintext,
		    const struct bytes *key, const struct bytes *iv)
{
	struct bytes *expkey = NULL, *prevblock = NULL, *padded = NULL,
		     *ciphertext = NULL;
	int success = 0;

	if (impl == NULL || plaintext == NULL || iv == NULL)
		goto cleanup;

	expkey = impl->expand_key(key);
	if (expkey == NULL)
		goto cleanup;

	const size_t blocksize = impl->blocksize();
	if (iv->len != blocksize)
		goto cleanup;

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
		/* add the previous block (the iv on the first iteration) to
		   the plaintext block */
		err |= bytes_xor(ptblock, i == 0 ? iv : prevblock);
		/* the ciphertext block is the xored block encrypted */
		ctblock = impl->encrypt(ptblock, expkey);
		bytes_free(ptblock);
		/* add the computed block to to the ciphertext */
		err |= bytes_put(ciphertext, offset, ctblock);
		/* save the current ciphertext block for the next iteration */
		bytes_free(prevblock);
		prevblock = ctblock;
	}
	if (err)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(expkey);
	bytes_free(prevblock);
	bytes_free(padded);
	if (!success) {
		bytes_free(ciphertext);
		ciphertext = NULL;
	}
	return (ciphertext);
}


struct bytes *
cbc_decrypt(const struct block_cipher *impl, const struct bytes *ciphertext,
		    const struct bytes *key, const struct bytes *iv)
{
	struct bytes *expkey = NULL, *prevblock = NULL, *plaintext = NULL,
		     *unpadded = NULL;
	int success = 0;

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
		/* decrypt it, the result is not the plaintext block yet */
		ptblock = impl->decrypt(ctblock, expkey);
		/* add the previous block (the iv on the first iteration) to
		   the decrypted one to find the plaintext block */
		err |= bytes_xor(ptblock, i == 0 ? iv : prevblock);
		/* save the current ciphertext block for the next iteration */
		bytes_free(prevblock);
		prevblock = ctblock;
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
	bytes_free(prevblock);
	bytes_free(plaintext);
	if (!success) {
		bytes_free(unpadded);
		unpadded = NULL;
	}
	return (unpadded);
}
