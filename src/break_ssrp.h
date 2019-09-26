#ifndef BREAK_SSRP_H
#define BREAK_SSRP_H
/*
 * break_ssrp.h
 *
 * Simplified Secure Remote Password (SSRP) mitm stuff for cryptopals.com
 * challenges.
 */
#include "bytes.h"
#include "bignum.h"
#include "ssrp.h"


/*
 * opaque struct used by server created by ssrp_local_mitm_server_new().
 */
struct ssrp_local_mitm_server_opaque {
	struct bignum *N, *g;
	struct bytes *salt, *token;
	struct bignum *A, *b, *B, *u;
};


/*
 * Create a new SSRP MITM Server struct with the given parameters.
 *
 * Returns a new ssrp_server struct that must be passed to its free function
 * member, or NULL on failure.
 */
struct ssrp_server	*ssrp_local_mitm_server_new(void);

/*
 * Attempt to crack the negociation password given a server having already
 * finalized the SSRP handshake and a dictionary of passwords.
 *
 * Returns the cracked password that must be passed to free(3) after use,
 * or NULL on failure.
 */
char	*ssrp_local_mitm_password(const struct ssrp_server *server,
		    const char **dict, size_t count);

#endif /* ndef BREAK_SSRP_H */
