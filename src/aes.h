#ifndef AES_H
#define AES_H
/*
 * aes.h
 *
 * AES stuff for cryptopals.com challenges.
 */
#include "bytes.h"
#include "block_cipher.h"


/*
 * Returns this block cipher key length in bytes, 16.
 */
size_t	aes_128_keylength(void);

/*
 * Returns this block cipher expanded key length in bytes, 176.
 */
size_t	aes_128_expkeylength(void);

/*
 * Returns this block cipher block size in bytes, 16.
 */
size_t	aes_128_blocksize(void);

/*
 * Returns the expanded key by performing the Rijndael key schedule on the
 * provided key.
 *
 * see https://en.wikipedia.org/wiki/Rijndael_key_schedule
 */
struct bytes	*aes_128_expand_key(const struct bytes *key);

/*
 * Encrypt/Decrypt the given block under the provided expanded key. Returns 0 on
 * success and -1 on failure.
 */
int	aes_128_encrypt(struct bytes *block, const struct bytes *expkey);
int	aes_128_decrypt(struct bytes *block, const struct bytes *expkey);


/*
 * expose the aes_128 routines as a block cipher
 */
static const struct block_cipher aes_128 = {
	.keylength    = aes_128_keylength,
	.expkeylength = aes_128_expkeylength,
	.blocksize    = aes_128_blocksize,
	.expand_key   = aes_128_expand_key,
	.encrypt      = aes_128_encrypt,
	.decrypt      = aes_128_decrypt,
};

#endif /* ndef AES_H */
