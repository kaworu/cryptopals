#ifndef BREAK_ECB_H
#define BREAK_ECB_H
/*
 * break_ecb.h
 *
 * ECB analysis stuff for cryptopals.com challenges.
 */
#include "bytes.h"
#include "cookie.h"


/*
 * Detect if the provided buffer is encrypted via AES-128 in ECB mode.
 *
 * Note that this function should also be able to detect AES-256 in ECB mode,
 * and more generally any block cipher with a block size of 16 bytes in ECB
 * mode.
 *
 * Returns 0 on success, -1 if either argument is NULL or an error arise.
 */
int	ecb_detect(const struct bytes *buf, double *score_p);

/*
 * ECB/CBC Encryption Oracle as described by Set 2 / Challenge 11.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(), or NULL if malloc(3) failed.
 */
struct bytes	*ecb_cbc_encryption_oracle(const struct bytes *input, int *ecb);

/*
 * ECB/CBC Decryption Oracle helper.
 *
 * Returns the input that ecb_cbc_detect() expect to have been encrypted by
 * ecb_cbc_encryption_oracle(). Returns a pointer to a newly allocated bytes
 * struct that should passed to bytes_free(), or NULL if malloc(3) failed.
 */
struct bytes	*ecb_cbc_detect_input(void);

/*
 * ECB/CBC Decryption Oracle as described by Set 2 / Challenge 11.
 *
 * Returns -1 on error, 1 if the given buffer was the ecb_cbc_detect_input()
 * encrypted in ECB mode, 0 otherwise.
 */
int	ecb_cbc_detect(const struct bytes *buf);

/*
 * ECB Encryption Oracle as described by Set 2 / Challenge 12.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(), or NULL if malloc(3) failed or if any given parameter is NULL.
 */
struct bytes	*ecb_byte_at_a_time_oracle(const struct bytes *payload,
		    const struct bytes *message,
		    const struct bytes *key);

/*
 * ECB Decryption Oracle as described by Set 2 / Challenge 12.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(), or NULL if malloc(3) failed or if any given parameter is NULL.
 */
struct bytes	*ecb_byte_at_a_time_breaker(const void *message,
		    const void *key);

/*
 * ECB Encryption Oracle as described by Set 2 / Challenge 13.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(), or NULL if malloc(3) failed or if any given parameter is NULL.
 */
struct bytes	*ecb_cut_and_paste_profile_for(const char *email,
		    const struct bytes *key);

/*
 * ECB Decryption Oracle as described by Set 2 / Challenge 13.
 *
 * Returns a pointer to a newly allocated cookie struct that should passed to
 * cookie_free(), or NULL if the decryption failed, cookie decoding failed,
 * malloc(3) failed, or if any given parameter is NULL.
 */
struct cookie	*ecb_cut_and_paste_profile(const struct bytes *ciphertext,
		    const struct bytes *key);

/*
 * Admin profile generator using ecb_cut_and_paste_profile_for() as Oracle as
 * described by Set 2 / Challenge 13.
 *
 * Returns a pointer to a newly allocated bytes struct that should passed to
 * bytes_free(), or NULL if malloc(3) failed or the Oracle failed.
 */
struct bytes *ecb_cut_and_paste_profile_breaker(const void *key);

#endif /* ndef BREAK_ECB_H */
