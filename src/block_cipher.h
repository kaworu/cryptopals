#ifndef BLOCK_CIPHER_H
#define BLOCK_CIPHER_H
/*
 * block_cipher.h
 *
 * Block Cipher interfaces.
 */
#include "bytes.h"


/*
 * Define a block cipher that can be used by different block cipher mode of
 * operation.
 */
struct block_cipher {
	/* this block cipher's expected key length in bytes */
	size_t	(*keylength)(void);
	/* this block cipher's block size in bytes */
	size_t	(*blocksize)(void);
	/* primitive routine used for encrypting */
	struct bytes	*(*encrypt)(const struct bytes *input, const struct bytes *key);
	/* primitive routine used for decrypting */
	struct bytes	*(*decrypt)(const struct bytes *input, const struct bytes *key);
};

#endif /* ndef BLOCK_CIPHER_H */
