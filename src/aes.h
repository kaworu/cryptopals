#ifndef AES_H
#define AES_H
/*
 * aes.h
 *
 * AES stuff for cryptopals.com challenges.
 *
 * Mosty just wrapping the OpenSSL API.
 */
#include "bytes.h"

/**
 * Encrypt a given plaintext via AES-128 in ECB mode under the provided key.
 *
 * Returns the ciphertext or NULL on error.
 */
struct bytes	*aes_128_ecb_encrypt(const struct bytes *plaintext,
		    const struct bytes *key);

/**
 * Decrypt a given ciphertext encrypted via AES-128 in ECB mode under the
 * provided key.
 *
 * Returns the ciphertext or NULL on error.
 */
struct bytes	*aes_128_ecb_decrypt(const struct bytes *ciphertext,
		    const struct bytes *key);

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

#endif /* ndef AES_H */
