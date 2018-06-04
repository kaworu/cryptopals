/*
 * ctr.c
 *
 * Counter mode of operation.
 */
#include "xor.h"
#include "ctr.h"
#include "nope.h"
#include "aes.h"


/*
 * Encrypt the given plaintext under the provided key.
 */
struct bytes	*ctr_crypt(const struct block_cipher *impl,
		    const struct bytes *input, const struct bytes *key,
		    uint64_t nonce);

/*
 * Helper to create the stream block to be encrypted.
 */
static void	uint64_to_bytes_le(uint64_t x, uint8_t *p);


struct bytes *
nope_ctr_encrypt(const struct bytes *plaintext, const struct bytes *key,
		    uint64_t nonce)
{
	return (ctr_crypt(&nope, plaintext, key, nonce));
}


struct bytes *
nope_ctr_decrypt(const struct bytes *ciphertext, const struct bytes *key,
		    uint64_t nonce)
{
	return (ctr_crypt(&nope, ciphertext, key, nonce));
}


struct bytes *
aes_128_ctr_encrypt(const struct bytes *plaintext, const struct bytes *key,
		    uint64_t nonce)
{
	return (ctr_crypt(&aes_128, plaintext, key, nonce));
}


struct bytes *
aes_128_ctr_decrypt(const struct bytes *ciphertext, const struct bytes *key,
		    uint64_t nonce)
{
	return (ctr_crypt(&aes_128, ciphertext, key, nonce));
}


struct bytes *
ctr_crypt(const struct block_cipher *impl, const struct bytes *input,
		    const struct bytes *key, uint64_t nonce)
{
	struct bytes *expkey = NULL, *stream = NULL, *output = NULL;
	int success = 0;

	if (impl == NULL || input == NULL)
		goto cleanup;

	expkey = impl->expand_key(key);
	if (expkey == NULL)
		goto cleanup;

	const size_t blocksize = impl->blocksize();
	if (blocksize != 16)
		goto cleanup;

	/* the keystream block */
	stream = bytes_zeroed(blocksize);
	if (stream == NULL)
		goto cleanup;

	/* create the plaintext buffer */
	output = bytes_zeroed(input->len);
	if (output == NULL)
		goto cleanup;

	/* compute the complete block count */
	const size_t nblock = input->len / blocksize;

	/* main encryption loop, process the input by chunk of blocksize */
	int err = 0;
	for (uint64_t i = 0; i <= nblock; i++) {
		struct bytes *block;
		const size_t offset = i * blocksize;
		/* compute the input block length. If we're at the last block it
		   may be incomplete. */
		const size_t inlen = (i == nblock ?
			    input->len % blocksize : blocksize);
		/* get the current input block */
		block = bytes_slice(input, offset, inlen);
		/* generate the current stream block */
		uint64_to_bytes_le(nonce, stream->data + 0);
		uint64_to_bytes_le(i,     stream->data + 8);
		err |= impl->encrypt(stream, expkey);
		if (stream->len > inlen) {
			/*
			 * truncate the stream block to the input block length.
			 */
			struct bytes *stblock = stream;
			stream = bytes_slice(stream, 0, inlen);
			bytes_free(stblock);
		}
		err |= bytes_xor(block, stream);
		/* populate the output */
		err |= bytes_put(output, offset, block);
		bytes_free(block);
	}
	if (err)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(stream);
	bytes_free(expkey);
	if (!success) {
		bytes_free(output);
		output = NULL;
	}
	return (output);
}


static void
uint64_to_bytes_le(uint64_t x, uint8_t *p)
{
	for (size_t i = 0; i < 8; i++)
		p[i] = (x >> (i * 8)) & 0xff;
}
