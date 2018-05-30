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
 * Returns this block cipher expanded key length in bytes, 1.
 *
 * The expanded key length is choosen to be different from the key length, to
 * avoid confusion.
 */
size_t	nope_expkeylength(void);

/*
 * Returns this block cipher block size in bytes, 16.
 */
size_t	nope_blocksize(void);

/*
 * Returns a copy of the provided key.
 */
struct bytes	*nope_expand_key(const struct bytes *key);

/*
 * Returns a copy of the provided input, regardless of the given expanded key.
 */
struct bytes	*nope_crypt(const struct bytes *input, const struct bytes *expkey);


/*
 * expose the nope routines as a block cipher
 */
static const struct block_cipher nope = {
	.keylength    = nope_keylength,
	.expkeylength = nope_expkeylength,
	.blocksize    = nope_blocksize,
	.expand_key   = nope_expand_key,
	.encrypt      = nope_crypt,
	.decrypt      = nope_crypt,
};

#endif /* ndef NOPE_H */
