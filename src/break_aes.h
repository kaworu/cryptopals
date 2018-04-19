#ifndef BREAK_AES_H
#define BREAK_AES_H
/*
 * break_aes.h
 *
 * AES analysis stuff for cryptopals.com challenges.
 */
#include "bytes.h"


/**
 * Detect if the provided buffer is encrypted via AES-128 in ECB mode.
 *
 * Note that this function should also be able to detect AES-256 in ECB mode,
 * and more generally any block cipher with a block size of 16 bytes in ECB
 * mode.
 *
 * Returns 0 on success, -1 if either argument is NULL or an error arise.
 */
int	aes_128_ecb_detect(const struct bytes *buf, double *score_p);

/**
 * AES ECB/CBC Encryption Oracle as described by Set 2 / Challenge 11.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(), or NULL if malloc(3) failed.
 */
struct bytes	*aes_128_ecb_cbc_encryption_oracle(const struct bytes *input,
		    int *ecb);

/**
 * AES ECB/CBC Decryption Oracle helper.
 *
 * Returns the input that aes_128_ecb_cbc_detect() expect to have been encrypted
 * by aes_128_ecb_cbc_encryption_oracle().
 */
struct bytes	*aes_128_ecb_cbc_detect_input(void);

/**
 * AES ECB/CBC Decryption Oracle as described by Set 2 / Challenge 11.
 *
 * Returns -1 on error, 1 if the given buffer was the
 * aes_128_ecb_cbc_detect_input() encrypted in ECB mode, 0 otherwise.
 */
int	aes_128_ecb_cbc_detect(const struct bytes *buf);

#endif /* ndef BREAK_AES_H */
