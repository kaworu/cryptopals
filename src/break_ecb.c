/*
 * break_ecb.c
 *
 * ECB analysis stuff for cryptopals.com challenges.
 */
#include <string.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "compat.h"
#include "cookie.h"
#include "aes.h"
#include "break_ecb.h"


int
ecb_detect(const struct bytes *buf, double *score_p)
{
	const EVP_CIPHER *cipher = EVP_aes_128_ecb();
	const size_t blocksize = EVP_CIPHER_block_size(cipher);
	size_t nmatch = 0;
	int success = 0;

	/* sanity checks */
	if (buf == NULL || score_p == NULL)
		goto cleanup;

	const size_t nblocks = buf->len / blocksize;
	size_t rounds = 0;
	for (size_t i = 0; i < nblocks; i++) {
		for (size_t j = i + 1; j < nblocks; j++) {
			struct bytes *lhs, *rhs;
			rounds += 1;
			lhs = bytes_slice(buf, i * blocksize, blocksize);
			rhs = bytes_slice(buf, j * blocksize, blocksize);
			if (lhs == NULL || rhs == NULL) {
				bytes_free(lhs);
				bytes_free(rhs);
				goto cleanup;
			}
			/* NOTE: we don't need const time comparison here */
			if (bytes_bcmp(lhs, rhs) == 0)
				nmatch += 1;
			bytes_free(lhs);
			bytes_free(rhs);
		}
	}
	*score_p = (double)nmatch / rounds;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	return (success ? 0 : -1);
}


struct bytes *
ecb_cbc_encryption_oracle(const struct bytes *input, int *ecb)
{
	const EVP_CIPHER *cipher = EVP_aes_128_cbc();
	struct bytes *random = NULL, *before = NULL, *after = NULL;
	struct bytes *padded = NULL;
	struct bytes *key = NULL, *iv = NULL, *output = NULL;
	int success = 0;

	/* sanity check */
	if (input == NULL)
		goto cleanup;

	/* some random bytes we'll be using */
	random = bytes_randomized(3);
	if (random == NULL)
		goto cleanup;

	/* random key generation */
	key = bytes_randomized((size_t)EVP_CIPHER_key_length(cipher));
	/* random IV generation */
	iv = bytes_randomized((size_t)EVP_CIPHER_iv_length(cipher));

	/* leading pad */
	before = bytes_randomized(5 + random->data[0] % 6);
	/* trailing pad */
	after = bytes_randomized(5 + random->data[1] % 6);
	const struct bytes *const parts[] = { before, input, after };
	/* build the padded input */
	padded = bytes_joined_const(parts, sizeof(parts) / sizeof(*parts));

	/* choose if we're using ECB mode with a 50% probability */
	const int use_ecb_mode = random->data[2] & 0x1;
	if (use_ecb_mode)
		output = aes_128_ecb_encrypt(padded, key);
	else /* use CBC mode */
		output = aes_128_cbc_encrypt(padded, key, iv);
	if (output == NULL)
		goto cleanup;

	if (ecb != NULL)
		*ecb = use_ecb_mode;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(padded);
	bytes_free(after);
	bytes_free(before);
	bytes_free(iv);
	bytes_free(key);
	bytes_free(random);
	if (!success) {
		bytes_free(output);
		output = NULL;
	}
	return (output);
}


struct bytes *
ecb_cbc_detect_input(void)
{
	const EVP_CIPHER *cipher = EVP_aes_128_ecb();
	const size_t blocksize = EVP_CIPHER_block_size(cipher);

	/*
	 * The oracle will pad with 5 to 10 bytes. Thus, this first and last
	 * blocks are "lost" for analysis. To be safe, we want at least three
	 * equals blocks to detect ECB mode, so let's encrypt four of them
	 * (because the padding will compromise only up to the first block).
	 */
	const size_t len = 4 * blocksize;
	return (bytes_zeroed(len));
}


int
ecb_cbc_detect(const struct bytes *buf)
{
	const EVP_CIPHER *cipher = EVP_aes_128_ecb();
	const size_t blocksize = EVP_CIPHER_block_size(cipher);
	struct bytes *blocks = NULL;
	int ecb = -1;
	int success = 0;

	/* sanity checks */
	if (buf == NULL || buf->len < 5 * blocksize)
		goto cleanup;

	/* we need to drop the first block because it has been messed
	   up by the padding */
	blocks = bytes_slice(buf, blocksize, 3 * blocksize);

	double score = -1;
	if (ecb_detect(blocks, &score) != 0)
		goto cleanup;

	/*
	 * in ECB mode the three ciphertext blocks should have the sames bytes
	 * (because the plaintext was the sames bytes), thus we should end up
	 * with a perfect score.
	 */
	ecb = (score == 1.0);

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(blocks);
	return (success ? ecb : -1);
}


struct bytes *
ecb_byte_at_a_time_oracle12(
		    const struct bytes *payload,
		    const struct bytes *message,
		    const struct bytes *key)
{
	struct bytes *prefix, *result;

	prefix = bytes_from_str("");
	result = ecb_byte_at_a_time_oracle14(prefix, payload, message, key);
	bytes_free(prefix);
	return (result);
}


struct bytes *
ecb_byte_at_a_time_breaker12(const void *message, const void *key)
{
	struct bytes *prefix, *result;

	prefix = bytes_from_str("");
	result = ecb_byte_at_a_time_breaker14(prefix, message, key);
	bytes_free(prefix);
	return (result);
}


struct bytes *
ecb_cut_and_paste_profile_for(const char *email,
		    const struct bytes *key)
{
	struct cookie *profile = NULL;
	char *desc = NULL;
	struct bytes *plaintext = NULL, *ciphertext = NULL;
	int success = 0;

	profile = cookie_alloc();
	if (cookie_append(profile, "email", email) != 0)
		goto cleanup;
	if (cookie_append(profile, "uid", "10") != 0)
		goto cleanup;
	if (cookie_append(profile, "role", "user") != 0)
		goto cleanup;
	desc = cookie_encode(profile);
	plaintext = bytes_from_str(desc);
	ciphertext = aes_128_ecb_encrypt(plaintext, key);

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(plaintext);
	freezero(desc, desc == NULL ? 0 : strlen(desc));
	cookie_free(profile);
	if (!success) {
		bytes_free(ciphertext);
		ciphertext = NULL;
	}
	return (ciphertext);
}


struct cookie *
ecb_cut_and_paste_profile(const struct bytes *ciphertext,
		    const struct bytes *key)
{
	struct bytes *plaintext = aes_128_ecb_decrypt(ciphertext, key);
	char *desc = bytes_to_str(plaintext);
	bytes_free(plaintext);
	struct cookie *profile = cookie_decode(desc);
	freezero(desc, desc == NULL ? 0 : strlen(desc));
	return (profile);
}


struct bytes *
ecb_cut_and_paste_profile_breaker(const void *key)
{
#define oracle(x)	ecb_cut_and_paste_profile_for((x), key);
	struct bytes *head = NULL, *tail = NULL, *admin = NULL;
	int success = 0;

	/*
	 * We could find the blocksize, expansion length, and detect ECB here
	 * just like in ecb_byte_at_a_time_breaker() but let's skip this part.
	 */
	const size_t blocksize = EVP_CIPHER_block_size(EVP_aes_128_ecb());
	const size_t explen = strlen("email=&uid=??&role=user");

	/*
	 * We want to craft an email such as the `role=' part of the expansion
	 * is at the very end of a block, visually:
	 *     [email=AAA...&uid=??&role=][user . padding]
	 *                  \_________________/
	 *                       expansion
	 */
	size_t emaillen = blocksize - (explen - strlen("user")) % blocksize;
	struct bytes *email = bytes_repeated(emaillen, (uint8_t)'A');
	char *email_str = bytes_to_str(email);
	bytes_free(email);
	struct bytes *ciphertext = oracle(email_str);
	freezero(email_str, email_str == NULL ? 0 : strlen(email_str));
	if (ciphertext == NULL || ciphertext->len < blocksize)
		goto cleanup;
	/* the last block is the [user . padding] part, we want every blocks but
	   this one */
	const size_t nblocks = ciphertext->len / blocksize;
	head = bytes_slice(ciphertext, 0, (nblocks - 1) * blocksize);
	bytes_free(ciphertext);

	/*
	 * Now we want to craft an email such as:
	 *     [email=AAA...][admin . padding][&uid=??&role=user . padding]
	 *            \_____________________/
	 *                    email
	 */
	emaillen = blocksize - strlen("email=") % blocksize;
	email = bytes_repeated(emaillen + blocksize, (uint8_t)'A');
	struct bytes *role = bytes_from_str("admin");
	struct bytes *padded = bytes_pkcs7_padded(role, blocksize);
	bytes_free(role);
	(void)bytes_put(email, emaillen, padded);
	bytes_free(padded);
	email_str = bytes_to_str(email);
	bytes_free(email);
	ciphertext = oracle(email_str);
	freezero(email_str, email_str == NULL ? 0 : strlen(email_str));
	if (ciphertext == NULL || ciphertext->len < blocksize)
		goto cleanup;
	/* We only want the [admin . padding] block */
	const size_t skip = (strlen("email=") + emaillen) / blocksize;
	tail = bytes_slice(ciphertext, skip * blocksize, blocksize);
	bytes_free(ciphertext);

	/*
	 * Finally construct the admin profile ciphertext by appending the head
	 * part to the tail, visually:
	 *
	 *     [email=AAA...&uid=??&role=][admin . padding]
	 *     \_________________________/\_______________/
	 *                head                  tail
	 */
	const struct bytes *const parts[] = { head, tail };
	admin = bytes_joined_const(parts, sizeof(parts) / sizeof(*parts));

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(tail);
	bytes_free(head);
	if (!success) {
		bytes_free(admin);
		admin = NULL;
	}
	return (admin);
#undef oracle
}


struct bytes *
ecb_byte_at_a_time_oracle14(
		    const struct bytes *prefix,
		    const struct bytes *payload,
		    const struct bytes *message,
		    const struct bytes *key)
{
	struct bytes *input = NULL, *output = NULL;
	int success = 0;

	/* sanity checks */
	if (prefix == NULL || payload == NULL || message == NULL || key == NULL)
		goto cleanup;

	const struct bytes *const parts[] = { prefix, payload, message };
	input = bytes_joined_const(parts, sizeof(parts) / sizeof(*parts));

	output = aes_128_ecb_encrypt(input, key);
	if (output == NULL)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	bytes_free(input);
	if (!success) {
		bytes_free(output);
		output = NULL;
	}
	return (output);
}


struct bytes *
ecb_byte_at_a_time_breaker14(
		    const void *prefix,
		    const void *message,
		    const void *key)
{
#define oracle(x)	ecb_byte_at_a_time_oracle14(prefix, (x), message, key)
	const EVP_CIPHER *cipher = EVP_aes_128_ecb();
	const size_t expected_blocksize = EVP_CIPHER_block_size(cipher);
	size_t blocksize = 0;
	size_t totallen = 0, prefixlen = 0, msglen = 0;
	struct bytes *payload = NULL, *ciphertext = NULL;
	struct bytes *recovered = NULL;
	int success = 0;

	/*
	 * find the blocksize and the "total length"
	 * (i.e. the prefix length + the message length)
	 */

	size_t prevsize = 0;
	for (size_t i = 0; i <= expected_blocksize && blocksize == 0; i++) {
		payload = bytes_repeated(i, (uint8_t)'A');
		ciphertext = oracle(payload);
		bytes_free(payload);
		if (ciphertext == NULL)
			goto cleanup;
		if (!prevsize) {
			prevsize = ciphertext->len;
		} else if (prevsize < ciphertext->len) {
			blocksize = ciphertext->len - prevsize;
			/* ciphertext is [p . p' . m . p''] where p is the
			   prefix, p' is the the payload, m is the message, and
			   p'' a full block of padding. */
			totallen = ciphertext->len - i - blocksize;
		}
		bytes_free(ciphertext);
	}
	if (blocksize != expected_blocksize)
		goto cleanup;

	/*
	 * detect ECB mode, finding the prefix block count on the way.
	 */

	/* generate 4 blocks of payload, so that we would find at least three
	   full blocks intact as the first one may be "mixed" with the prefix */
	payload = bytes_zeroed(4 * blocksize);
	ciphertext = oracle(payload);
	bytes_free(payload);
	if (ciphertext == NULL)
		goto cleanup;
	int ecb_found = 0;
	for (size_t i = 0; i < ciphertext->len && !ecb_found; i += blocksize) {
		double score = -1;
		struct bytes *chunk = bytes_slice(ciphertext, i, 3 * blocksize);
		const int ret = ecb_detect(chunk, &score);
		bytes_free(chunk);
		if (ret != 0) {
			break;
		} else if (score == 1.0) {
			prefixlen = i;
			ecb_found = 1;
		}
	}
	bytes_free(ciphertext);
	if (!ecb_found)
		goto cleanup;
	/*
	 * Here we know that the prefix fit in `prefixlen', a multiple of
	 * the blocksize for now.
	 */
	if (prefixlen == 0) {
		/* the prefix is empty, skip the prefixlen detection codepath */
		goto recover;
	}

	/*
	 * prefix length detection.
	 *
	 * We study the last prefix block "padded" with our payload decreasingly
	 * bytes by bytes. Initally, the last block having part of the prefix
	 * (p) is of the form
	 *
	 *     [p . 0x0*]
	 *
	 * where 0x0* our payload (zeros repeated). We use this block as
	 * reference (ref0). Once the payload is "small enough", the first byte
	 * of the message (m0) join the party in the block, yielding the form
	 *
	 *     [p . 0x0* . m0]
	 *
	 * At that point we should see a difference with ref0. The caveat is
	 * that we won't see a difference with ref0 if m0 == 0x0, so we
	 * duplicate the tests with 0x1 (arbitrarily, any other value than 0x0
	 * would do). That way at least one of them will change when m0 join the
	 * block.
	 */
	/* build ref0 and ref1 */
	const size_t off = prefixlen - blocksize;
	payload = bytes_repeated(blocksize, 0x0);
	ciphertext = oracle(payload);
	bytes_free(payload);
	struct bytes *ref0 = bytes_slice(ciphertext, off, blocksize);
	bytes_free(ciphertext);
	if (ref0 == NULL)
		goto cleanup;
	payload = bytes_repeated(blocksize, 0x1);
	ciphertext = oracle(payload);
	bytes_free(payload);
	struct bytes *ref1 = bytes_slice(ciphertext, off, blocksize);
	bytes_free(ciphertext);
	if (ref1 == NULL)
		goto cleanup;
	/* decrease the payload one byte at a time */
	for (size_t i = 1; i <= blocksize; i++) {
		payload = bytes_repeated(blocksize - i, 0x0);
		ciphertext = oracle(payload);
		bytes_free(payload);
		struct bytes *block0 = bytes_slice(ciphertext, off, blocksize);
		bytes_free(ciphertext);
		payload = bytes_repeated(blocksize - i, 0x1);
		ciphertext = oracle(payload);
		bytes_free(payload);
		struct bytes *block1 = bytes_slice(ciphertext, off, blocksize);
		bytes_free(ciphertext);
		if (block0 == NULL || block1 == NULL) {
			bytes_free(block1);
			bytes_free(block0);
			bytes_free(ref1);
			bytes_free(ref0);
			goto cleanup;
		}
		const int cmp0 = bytes_bcmp(ref0, block0);
		const int cmp1 = bytes_bcmp(ref1, block1);
		bytes_free(block0);
		bytes_free(block1);
		if (cmp0 != 0 || cmp1 != 0) {
			prefixlen = prefixlen - blocksize + i - 1;
			break;
		}
	}
	bytes_free(ref1);
	bytes_free(ref0);

	/* FALLTHROUGH */
recover:
	/* now that we know both the (prefix + message) length and the prefix
	   length, we can easily compute the exact message length */
	msglen = totallen - prefixlen;
	/* allocate the recovered message, initially filled with 0 */
	recovered = bytes_zeroed(msglen);
	if (recovered == NULL)
		goto cleanup;
	/* count of bytes to ignore, basically the prefix + prefix padding */
	const size_t ignblock = prefixlen / blocksize + 1;
	/* the length of the prefix padding we need to generate */
	const size_t prefixpadlen = ignblock * blocksize - prefixlen;
	/* count of block needed to hold the full message */
	const size_t nblocks = msglen / blocksize + 1;
	/* a buffer holding our attempt at cracking the message bytes */
	payload = bytes_zeroed(prefixpadlen + nblocks * blocksize);
	if (payload == NULL)
		goto cleanup;
	/* offset of the last block in the ciphertext, the one holding the byte
	   we are guessing */
	const size_t coffset = (ignblock + nblocks - 1) * blocksize;
	/* processing loop, breaking one message byte at a time */
	for (size_t i = 1; i <= msglen; i++) {
		struct bytes *pre, *ct, *iblock;
		/* the index of the byte we are breaking in this iteration in
		   the ciphertext given by the oracle */
		const size_t index = prefixpadlen + nblocks * blocksize - i;
		/* pad the start of the choosen plaintext so that the byte at
		   index is at the very end of the block at coffset */
		pre = bytes_repeated(index, (uint8_t)'A');
		ct = oracle(pre);
		/* retrieve the block holding the byte we are guessing */
		iblock = bytes_slice(ct, coffset, blocksize);
		bytes_free(ct);
		/*
		 * Our guess payload is of the form [pre . guessed . guess].
		 * Just like for iblock `pre' is leading, `guessed' are the byte
		 * we already know and `guess' is our try for the byte at index.
		 */
		(void)bytes_put(payload, 0, pre);
		(void)bytes_sput(payload, index, recovered, 0, i);
		/* try each possible value for the byte until we find a match */
		for (uint16_t byte = 0; byte <= UINT8_MAX; byte++) {
			struct bytes *block;
			payload->data[index + i - 1] = (uint8_t)byte;
			ct = oracle(payload);
			block = bytes_slice(ct, coffset, blocksize);
			bytes_free(ct);
			const int found = (bytes_bcmp(block, iblock) == 0);
			bytes_free(block);
			if (found) {
				recovered->data[i - 1] = (uint8_t)byte;
				break;
			}
		}
		bytes_free(iblock);
		bytes_free(pre);
	}
	bytes_free(payload);

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		bytes_free(recovered);
		recovered = NULL;
	}
	return (recovered);
#undef oracle
}
