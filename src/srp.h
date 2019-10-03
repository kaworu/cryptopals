#ifndef SRP_H
#define SRP_H
/*
 * srp.h
 *
 * Secure Remote Password (SRP) stuff for cryptopals.com challenges.
 */
#include <sys/types.h>

#include "mpi.h"
#include "bytes.h"


/*
 * 32 bytes long salt, inspired by the test vectors from SRP for TLS
 * Authentication (see https://tools.ietf.org/html/rfc5054#appendix-B).
 */
#define	SRP_SALT_BYTES	32


/*
 * Used to interface with a SRP server.
 */
struct srp_server {
	/*
	 * Called by the client to start a SRP password-authenticated key
	 * agreement.
	 *
	 * The caller must provide I (its identity) and A (public number
	 * generated à-la Diffie-Hellman).
	 *
	 * On success salt_p is set to the SRP salt, B_p to the server's public
	 * number, and both salt_p and B_p must be passed to bytes_free() by the
	 * caller.
	 *
	 * Returns 0 on success, -1 if the identity is invalid or on failure.
	 */
	int	(*start)(struct srp_server *server, const struct bytes *I,
			const struct mpi *A, struct bytes **salt_p,
			struct mpi **B_p);

	/*
	 * Finalize a SRP password-authenticated key agreement by verifying the
	 * provided token.
	 *
	 * On both success and failure, the token created by start() (if any) is
	 * forgotten by the server once this function returns. Thus, if
	 * finalize() failed the client must re-start() the SRP agreement if
	 * desired.
	 *
	 * On success, a private shared key has been established between the
	 * client and the server that can be used for further communication.
	 *
	 * Returns 0 on success (the token is valid), -1 on failure.
	 */
	int	(*finalize)(struct srp_server *server, const struct bytes *token);

	/*
	 * Free the resource associated with the given srp_server struct.
	 *
	 * If not NULL, the data will be zero'd before freed.
	 */
	void	(*free)(struct srp_server *server);

	/* implementation defined data */
	void *opaque;
};

/*
 * opaque struct used by server created by srp_local_server_new().
 */
struct srp_local_server_opaque {
	/*
	 * The SRP parameters agreed upon with the client before any
	 * communication is made.
	 */
	struct bytes *I, *P;

	/*
	 * The shared private key derived from the SRP protocol.
	 */
	struct bytes *key;

	/*
	 * The private challenge that is created by start() and checked by
	 * finalize().
	 */
	struct bytes *token;
};

/*
 * opaque struct used by server created by srp_remote_server_new().
 */
struct srp_remote_server_opaque {
	/*
	 * The hostname and port of the remote SRP server.
	 */
	char *hostname, *port;

	/*
	 * Socket to the remote server.
	 */
	int sock;
};


/*
 * Used to interface with a SRP client.
 */
struct srp_client {
	/*
	 * The shared private key derived from the SRP protocol.
	 */
	struct bytes *key;

	/*
	 * Ask the client authenticate itself to the provided server.
	 *
	 * The client will try to start() and finalize() a SRP
	 * password-authenticated key agreement with the server. A successful
	 * authentication means that the client's credentials (it's identity and
	 * password) are recognized as correct by the server, and a private
	 * shared key is created that can be used for further communication.
	 *
	 * Returns 0 on success, -1 on failure.
	 */
	int	(*authenticate)(struct srp_client *client,
			    struct srp_server *server);

	/*
	 * Free the resource associated with the given srp_client struct.
	 *
	 * If not NULL, the data will be zero'd before freed.
	 */
	void	(*free)(struct srp_client *client);

	/* implementation defined data */
	void *opaque;
};

/*
 * opaque struct used by client created by srp_client_new().
 */
struct srp_client_opaque {
	/*
	 * The SRP parameters agreed upon with the server before any
	 * communication is made.
	 */
	struct bytes *I, *P;
};


/*
 * Set the SRP parameters N, g and k.
 *
 * Returns 0 on success, -1 on error. On success every non-NULL pointer given
 * are set to their SRP parameter values and must be passed to mpi_free() after
 * use.
 */
int	srp_parameters(struct mpi **N_p, struct mpi **g_p, struct mpi **k_p);

/*
 * Create a new SRP Server struct with the given parameters.
 *
 * The returned server will not perform network calls etc. but has instead the
 * SRP logic implemented directly in its member functions.
 *
 * Returns a new srp_server struct that must be passed to its free function
 * member, or NULL on failure.
 */
struct srp_server	*srp_local_server_new(const struct bytes *I,
		    const struct bytes *P);

/*
 * Create a new SRP Server struct that is going to communicate with a remote
 * server.
 *
 * Returns a new srp_server struct that must be passed to its free function
 * member, or NULL on failure.
 */
struct srp_server	*srp_remote_server_new(const char *hostname,
		    const char *port);

/*
 * Create a new SRP Client struct with the given parameters.
 *
 * Returns a new srp_client struct that must be passed to its free function
 * member, or NULL on failure.
 */
struct srp_client	*srp_client_new(const struct bytes *I,
		    const struct bytes *P);

/*
 * helpers to get a mpi from SHA-256(lhs concatenated to rhs)
 *
 * They are exposed here so that the Simplified SRP implementation can use them
 * too.
 */
struct mpi	*srp_mpi_from_sha256_bytes(const struct bytes *lhs,
		    const struct bytes *rhs);
struct mpi	*srp_mpi_from_sha256_mpis(const struct mpi *lhs,
		    const struct mpi *rhs);

#endif /* ndef SRP_H */
