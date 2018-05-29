#ifndef NOPE_H
#define NOPE_H
/*
 * nope.h
 *
 * A NULL block cipher, used for testing block cipher mode of operation.
 */
#include "bytes.h"
#include "block_cipher.h"


/*
 * Returns this block cipher key length in bytes, zero.
 */
size_t	nope_keylength(void);

/*
 * Returns this block cipher block size in bytes, 16.
 */
size_t	nope_blocksize(void);

/*
 * Returns a copy of the provided input, regardless of the given key.
 */
struct bytes	*nope_crypt(const struct bytes *input, const struct bytes *key);


/*
 * expose the nope routines as a block cipher
 */
static const struct block_cipher nope = {
	.keylength = nope_keylength,
	.blocksize = nope_blocksize,
	.encrypt   = nope_crypt,
	.decrypt   = nope_crypt,
};

#endif /* ndef NOPE_H */
