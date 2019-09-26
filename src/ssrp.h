#ifndef SSRP_H
#define SSRP_H
/*
 * ssrp.h
 *
 * Simplified Secure Remote Password (SSRP) stuff for cryptopals.com challenges.
 */
#include "bignum.h"
#include "bytes.h"


/*
 * Used to interface with a SSRP server.
 */
struct ssrp_server {
	/*
	 * Called by the client to start a SSRP password-authenticated key
	 * agreement.
	 *
	 * The caller must provide I (its identity) and A (public number
	 * generated à-la Diffie-Hellman).
	 *
	 * On success salt_p is set to the SRP salt, B_p to the server's public
	 * number, and u_p to a 128 bit random session number. salt_p, B_p, and
	 * u_p must be passed to bytes_free() by the caller.
	 *
	 * Returns 0 on success, -1 if the identity is invalid or on failure.
	 */
	int	(*start)(struct ssrp_server *server,
			    const struct bytes *I, const struct bignum *A,
			    struct bytes **salt_p, struct bignum **B_p,
			    struct bignum **u_p);

	/*
	 * Finalize a SSRP password-authenticated key agreement by verifying the
	 * provided token.
	 *
	 * On both success and failure, the token created by start() (if any) is
	 * forgotten by the server once this function returns. Thus, if
	 * finalize() failed the client must re-start() the SSRP agreement if
	 * desired.
	 *
	 * On success, a private shared key has been established between the
	 * client and the server that can be used for further communication.
	 *
	 * Returns 0 on success (the token is valid), -1 on failure.
	 */
	int	(*finalize)(struct ssrp_server *server, const struct bytes *token);

	/*
	 * Free the resource associated with the given ssrp_server struct.
	 *
	 * If not NULL, the data will be zero'd before freed.
	 */
	void	(*free)(struct ssrp_server *server);

	/* implementation defined data */
	void *opaque;
};

/*
 * opaque struct used by server created by ssrp_local_server_new().
 */
struct ssrp_local_server_opaque {
	/*
	 * The SSRP parameters agreed upon with the client before any
	 * communication is made.
	 */
	struct bytes *I, *P;

	/*
	 * The shared private key derived from the SSRP protocol.
	 */
	struct bytes *key;

	/*
	 * The private challenge that is created by start() and checked by
	 * finalize().
	 */
	struct bytes *token;
};

/*
 * Used to interface with a SSRP client.
 */
struct ssrp_client {
	/*
	 * The shared private key derived from the SSRP protocol.
	 */
	struct bytes *key;

	/*
	 * Ask the client authenticate itself to the provided server.
	 *
	 * The client will try to start() and finalize() a SSRP
	 * password-authenticated key agreement with the server. A successful
	 * authentication means that the client's credentials (it's identity and
	 * password) are recognized as correct by the server, and a private
	 * shared key is created that can be used for further communication.
	 *
	 * Returns 0 on success, -1 on failure.
	 */
	int	(*authenticate)(struct ssrp_client *client,
			    struct ssrp_server *server);

	/*
	 * Free the resource associated with the given ssrp_client struct.
	 *
	 * If not NULL, the data will be zero'd before freed.
	 */
	void	(*free)(struct ssrp_client *client);

	/* implementation defined data */
	void *opaque;
};

/*
 * opaque struct used by client created by ssrp_client_new().
 */
struct ssrp_client_opaque {
	/*
	 * The SSRP parameters agreed upon with the server before any
	 * communication is made.
	 */
	struct bytes *I, *P;
};


/*
 * Create a new SSRP Server struct with the given parameters.
 *
 * The returned server will not perform network calls etc. but has instead the
 * SSRP logic implemented directly in its member functions.
 *
 * Returns a new ssrp_server struct that must be passed to its free function
 * member, or NULL on failure.
 */
struct ssrp_server	*ssrp_local_server_new(const struct bytes *I,
		    const struct bytes *P);

/*
 * Create a new SSRP Client struct with the given parameters.
 *
 * Returns a new ssrp_client struct that must be passed to its free function
 * member, or NULL on failure.
 */
struct ssrp_client	*ssrp_client_new(const struct bytes *I,
		    const struct bytes *P);

#endif /* ndef SSRP_H */
