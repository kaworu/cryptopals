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
 * Returns this block cipher block size in bytes, 16.
 */
size_t	aes_128_blocksize(void);

/*
 * Encrypt/Decrypt the given input under the provided key.
 */
struct bytes	*aes_128_encrypt(const struct bytes *input, const struct bytes *key);
struct bytes	*aes_128_decrypt(const struct bytes *input, const struct bytes *key);


/*
 * expose the aes_128 routines as a block cipher
 */
static const struct block_cipher aes_128 = {
	.keylength = aes_128_keylength,
	.blocksize = aes_128_blocksize,
	.encrypt   = aes_128_encrypt,
	.decrypt   = aes_128_decrypt,
};


/*
 * Returns the count of AES round performed, 10.
 */
size_t	aes_128_rounds(void);

/*
 * Returns the expanded key by performing the Rijndael key schedule on the
 * provided key.
 *
 * see https://en.wikipedia.org/wiki/Rijndael_key_schedule
 */
struct bytes	*aes_128_expand_key(const struct bytes *key);

#endif /* ndef AES_H */
