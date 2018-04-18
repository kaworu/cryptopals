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

#endif /* ndef BREAK_AES_H */
