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
	/* this block cipher's expected expanded key length in bytes */
	size_t	(*expkeylength)(void);
	/* this block cipher's block size in bytes */
	size_t	(*blocksize)(void);
	/* perform the key expansion */
	struct bytes	*(*expand_key)(const struct bytes *key);
	/* primitive routine used for encrypting */
	int	(*encrypt)(struct bytes *block, const struct bytes *expkey);
	/* primitive routine used for decrypting */
	int	(*decrypt)(struct bytes *block, const struct bytes *expkey);
};

#endif /* ndef BLOCK_CIPHER_H */
