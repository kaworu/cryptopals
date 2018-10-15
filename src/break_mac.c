/*
 * break_mac.c
 *
 * MAC analysis stuff for cryptopals.com challenges.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "compat.h"
#include "sha1.h"
#include "md4.h"
#include "mac.h"
#include "break_mac.h"


/* Describe how a 64-bit length value is encoded as bytes */
enum length_encoding {
	HIGH_WORD_FIRST_BE,
	LOW_WORD_FIRST_LE,
};


/*
 * Returns the padding bytes for a message of the given length, or NULL on
 * error.
 */
static struct bytes	*sha1_padding(size_t len);
static struct bytes	*md4_padding(size_t len);
static struct bytes	*padding(size_t len, size_t blocksize,
		    enum length_encoding le);

/*
 * Perform a HTTP request to the server and compute request time.
 *
 * Returns -1 on error, the HTTP status code otherwise.
 */
static int	request_timing_leaking_server(const struct addrinfo *res,
		    const char *fmt, const struct bytes *mac,
		    struct timeval *tdiff_p);


int
extend_sha1_mac_keyed_prefix(const void *key,
		    const struct bytes *msg, const struct bytes *mac,
		    struct bytes **msg_p, struct bytes **mac_p)
#define oracle(m, c)	sha1_mac_keyed_prefix_verify(key, (m), (c))
{
	struct bytes *extension = NULL, *admin = NULL, *digest = NULL;
	struct sha1_ctx ctx;
	const size_t scount = sizeof(ctx.state) / sizeof(ctx.state[0]);
	uint32_t *h = NULL;
	size_t hcount = 0;
	int success = 0;

	if (msg == NULL || mac == NULL)
		goto cleanup;
	/* We'll try to break up to a keylength of 128 bytes. */
	if (msg->len >= ((UINT64_MAX - 128) / 8))
		goto cleanup;

	/* the extension payload */
	extension = bytes_from_str(";admin=true;");
	if (extension == NULL)
		goto cleanup;

	/* "unpack" the message's MAC so that we can use it to setup a SHA-1
	   Intermediate Hash State */
	h = bytes_to_uint32_be(mac, &hcount);
	if (h == NULL || hcount != scount)
		goto cleanup;

	/* try key length up to 1024-bit long, assume that it is a 8-bit
	   multiple */
	for (size_t keylen = 0; keylen <= 128; keylen++) {
		ctx.len = keylen + msg->len;
		/* generate the glue padding */
		struct bytes *glue = sha1_padding(ctx.len);
		if (glue == NULL)
			goto cleanup;
		/* update the length, now that we know the glue padding */
		ctx.len += glue->len;
		/* generate the full admin message */
		const struct bytes *const parts[] = { msg, glue, extension };
		admin = bytes_joined_const(parts, sizeof(parts) / sizeof(*parts));
		bytes_free(glue);
		if (admin == NULL)
			goto cleanup;
		/* reset the SHA-1 Intermediate Hash State */
		(void)memcpy(ctx.state, h, sizeof(ctx.state));
		/* extend the SHA-1 Intermediate Hash State */
		if (sha1_hash_ctx(&ctx, extension) != 0)
			goto cleanup;
		digest = bytes_from_uint32_be(ctx.state, scount);
		if (digest == NULL)
			goto cleanup;
		const int ret = oracle(admin, digest);
		if (ret == -1) /* error */
			goto cleanup;
		if (ret == 0) /* success */
			break;
		bytes_free(admin);
		admin = NULL;
		bytes_free(digest);
		digest = NULL;
	}
	if (admin == NULL || digest == NULL)
		goto cleanup;

	success = 1;

	if (msg_p != NULL) {
		*msg_p = admin;
		admin = NULL;
	}
	if (mac_p != NULL) {
		*mac_p = digest;
		digest = NULL;
	}

	/* FALLTHROUGH */
cleanup:
	bytes_free(admin);
	bytes_free(digest);
	freezero(h, hcount * sizeof(uint32_t));
	bytes_free(extension);
	return (success ? 0 : -1);
}
#undef oracle


int
extend_md4_mac_keyed_prefix(const void *key,
		    const struct bytes *msg, const struct bytes *mac,
		    struct bytes **msg_p, struct bytes **mac_p)
#define oracle(m, c)	md4_mac_keyed_prefix_verify(key, (m), (c))
{
	struct bytes *extension = NULL, *admin = NULL, *digest = NULL;
	struct md4_ctx ctx;
	const size_t scount = sizeof(ctx.state) / sizeof(ctx.state[0]);
	uint32_t *h = NULL;
	size_t hcount = 0;
	int success = 0;

	if (msg == NULL || mac == NULL)
		goto cleanup;
	/* We'll try to break up to a keylength of 128 bytes. */
	if (msg->len >= ((UINT64_MAX - 128) / 8))
		goto cleanup;

	/* the extension payload */
	extension = bytes_from_str(";admin=true;");
	if (extension == NULL)
		goto cleanup;

	/* "unpack" the message's MAC so that we can use it to setup a MD4
	   Intermediate Hash State */
	h = bytes_to_uint32_le(mac, &hcount);
	if (h == NULL || hcount != scount)
		goto cleanup;

	/* try key length up to 1024-bit long, assume that it is a 8-bit
	   multiple */
	for (size_t keylen = 0; keylen <= 128; keylen++) {
		ctx.len = keylen + msg->len;
		/* generate the glue padding */
		struct bytes *glue = md4_padding(ctx.len);
		if (glue == NULL)
			goto cleanup;
		/* update the length, now that we know the glue padding */
		ctx.len += glue->len;
		/* generate the full admin message */
		const struct bytes *const parts[] = { msg, glue, extension };
		admin = bytes_joined_const(parts, sizeof(parts) / sizeof(*parts));
		bytes_free(glue);
		if (admin == NULL)
			goto cleanup;
		/* reset the MD4 Intermediate Hash State */
		(void)memcpy(ctx.state, h, sizeof(ctx.state));
		/* extend the MD4 Intermediate Hash State */
		if (md4_hash_ctx(&ctx, extension) != 0)
			goto cleanup;
		digest = bytes_from_uint32_le(ctx.state, scount);
		if (digest == NULL)
			goto cleanup;
		const int ret = oracle(admin, digest);
		if (ret == -1) /* error */
			goto cleanup;
		if (ret == 0) /* success */
			break;
		bytes_free(admin);
		admin = NULL;
		bytes_free(digest);
		digest = NULL;
	}
	if (admin == NULL || digest == NULL)
		goto cleanup;

	success = 1;

	if (msg_p != NULL) {
		*msg_p = admin;
		admin = NULL;
	}
	if (mac_p != NULL) {
		*mac_p = digest;
		digest = NULL;
	}

	/* FALLTHROUGH */
cleanup:
	bytes_free(admin);
	bytes_free(digest);
	freezero(h, hcount * sizeof(uint32_t));
	bytes_free(extension);
	return (success ? 0 : -1);
}
#undef oracle


struct bytes *
break_timing_leaking_server(const char *hostname,
		    const char *port, const char *fmt, size_t maclen)
{
	struct bytes *mac = NULL;
	struct addrinfo hints;
	struct addrinfo *res = NULL, *res0 = NULL;
	int success = 0;

	/* sanity checks */
	if (hostname == NULL || fmt == NULL)
		goto cleanup;

	/* find the addresses for the given hostname (both IPv6 and IPv4).
	   Heavily based on OpenBSD's getaddrinfo(3) manpage example. */
	(void)memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(hostname, port, &hints, &res0) != 0)
		goto cleanup;
	for (res = res0; res != NULL; res = res->ai_next) {
		const int s = socket(res->ai_family, res->ai_socktype,
			    res->ai_protocol);
		if (s == -1)
			continue;
		const int ret = connect(s, res->ai_addr, res->ai_addrlen);
		(void)close(s);
		if (ret == 0) {
			/* ok we got one */
			break;
		}
	}
	if (res == NULL)
		goto cleanup;

	/* allocate enough space for the MAC we're trying to break */
	mac = bytes_zeroed(maclen);
	if (mac == NULL)
		goto cleanup;

	/* Perform one request to warm up the server (filesystem cache etc.) */
	(void)request_timing_leaking_server(res, fmt, mac, NULL);

	/* break one byte MAC byte at a time */
	for (size_t i = 0; i < mac->len; i++) {
		/* very naive heuristic, we try each possible byte value
		   remembering the one where the request took the most time */
		struct {
			struct timeval tv;
			uint8_t byte;
		} slow;
		timerclear(&slow.tv);
		slow.byte = 0;
		for (uint16_t byte = 0; byte <= UINT8_MAX; byte++) {
			struct timeval t;
			mac->data[i] = byte;
			if (request_timing_leaking_server(res, fmt, mac, &t) == -1)
				goto cleanup;
			if (timercmp(&t, &slow.tv, >)) {
				slow.tv.tv_sec  = t.tv_sec;
				slow.tv.tv_usec = t.tv_usec;
				slow.byte = (uint8_t)byte;
			}
		}
		mac->data[i] = slow.byte;
	}

	/* ultimately, verify that our guessed MAC is valid. The server should
	   respond with a "200 OK" HTTP status if we succeeded. */
	if (request_timing_leaking_server(res, fmt, mac, NULL) != 200)
		goto cleanup;

	success = 1;
	/* FALLTHROUGH */
cleanup:
	freeaddrinfo(res0);
	if (!success) {
		bytes_free(mac);
		mac = NULL;
	}
	return (mac);
}


static struct bytes *
sha1_padding(size_t len)
{
	return padding(len, sha1_blocksize(), HIGH_WORD_FIRST_BE);
}


static struct bytes *
md4_padding(size_t len)
{
	return padding(len, md4_blocksize(), LOW_WORD_FIRST_LE);
}


static struct bytes *
padding(size_t len, size_t blocksize, enum length_encoding le)
{
	/* max total message length, in bytes */
	struct bytes *padding = NULL;
	int success = 0;

	/* count of message bytes in the padded block */
	const size_t restlen = len % blocksize;
	/* count of padding bytes in the padded block */
	size_t padlen = blocksize - restlen;
	if (padlen < (1 + 8)) {
		/* not enough space for the leading 0x80 and total message
		   length in the last block, add one block. */
		padlen += blocksize;
	}

	/* allocate enough space to hold the padding bytes */
	padding = bytes_zeroed(padlen);
	if (padding == NULL)
		goto cleanup;

	/* leading `1' bit */
	padding->data[0] = 0x80;

	/* set the 64-bits message length (count of bits) in the last 8 bytes of
	   the padded block */
	const uint64_t nbits = len * 8;
	size_t i = padlen - 8;
	switch (le) {
	case HIGH_WORD_FIRST_BE:
		padding->data[i++] = nbits >> 56;
		padding->data[i++] = nbits >> 48;
		padding->data[i++] = nbits >> 40;
		padding->data[i++] = nbits >> 32;
		padding->data[i++] = nbits >> 24;
		padding->data[i++] = nbits >> 16;
		padding->data[i++] = nbits >>  8;
		padding->data[i++] = nbits >>  0;
		break;
	case LOW_WORD_FIRST_LE:
		padding->data[i++] = nbits >>  0;
		padding->data[i++] = nbits >>  8;
		padding->data[i++] = nbits >> 16;
		padding->data[i++] = nbits >> 24;
		padding->data[i++] = nbits >> 32;
		padding->data[i++] = nbits >> 40;
		padding->data[i++] = nbits >> 48;
		padding->data[i++] = nbits >> 56;
		break;
	}

	success = 1;
	/* FALLTHROUGH */
cleanup:
	if (!success) {
		bytes_free(padding);
		padding = NULL;
	}
	return (padding);
}


static int
request_timing_leaking_server(const struct addrinfo *res,
		    const char *fmt, const struct bytes *mac,
		    struct timeval *tdiff_p)
{
	char *hex = NULL, *path = NULL, *req = NULL;
	int plen = 0, rlen = 0;
	size_t psize = 0, rsize = 0;
	struct timeval t1, t2;
	int s = -1; /* socket */
	int success = 0, status = 0;
	/* just enough space to hold the first few bytes including the status
	   code, i.e "HTTP/1.0 200" */
	char rsp[12 + 1] = { 0 };

	/* sanity checks */
	if (res == NULL || fmt == NULL || mac == NULL)
		goto cleanup;

	/* encode the hex representation of mac and build the path */
	hex = bytes_to_hex(mac);
	if (hex == NULL)
		goto cleanup;
	plen = snprintf(NULL, 0, fmt, hex);
	if (plen == -1)
		goto cleanup;
	psize = (size_t)plen + 1;
	path = calloc(psize, sizeof(char));
	if (path == NULL)
		goto cleanup;
	if (snprintf(path, psize, fmt, hex) != plen)
		goto cleanup;
	/* now build the full request */
	const char *req_fmt = "GET %s HTTP/1.0\r\n\r\n";
	rlen = snprintf(NULL, 0, req_fmt, path);
	if (rlen == -1)
		goto cleanup;
	rsize = (size_t)rlen + 1;
	req = calloc(rsize, sizeof(char));
	if (req == NULL)
		goto cleanup;
	if (snprintf(req, rsize, req_fmt, path) != rlen)
		goto cleanup;

	/* initiate the connection to the server */
	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (s == -1)
		goto cleanup;
	if (connect(s, res->ai_addr, res->ai_addrlen) != 0)
		goto cleanup;

	/* perform the request while timing it */
	if (gettimeofday(&t1, NULL) != 0)
		goto cleanup;
	if (send(s, req, rlen, /* flags */0) != rlen)
		goto cleanup;
	/* waste no time in reading the data, we just want to get back as soon
	   as there is an answer from the server */
	if (recv(s, rsp, 0, /* flags */0) == -1)
		goto cleanup;
	if (gettimeofday(&t2, NULL) != 0)
		goto cleanup;
	/* now read the data that we're interested in */
	if (recv(s, rsp, sizeof(rsp) - 1, /* flags */0) == -1)
		goto cleanup;

	/*
	 * Consume all the bytes that were sent by the server. This is needed in
	 * order to avoid closing the socket too early and exhaust the server
	 * sending buffer(s)
	 */
	char buf[BUFSIZ];
	while (recv(s, buf, sizeof(buf), /* flags */0) > 0);

	/* check that the response preamble match what we expect */
	const char *http_1_0 = "HTTP/1.0 ";
	if (strncmp(http_1_0, rsp, strlen(http_1_0)) != 0)
		goto cleanup;

	/* parse the HTTP status code */
	const char *p = rsp + strlen(http_1_0);
	char *ep = NULL;
	errno = 0;
	const unsigned long int ulval = strtoul(p, &ep, /* base */10);
	if (p[0] == '\0' || *ep != '\0') /* not a number */
		goto cleanup;
	if (errno == ERANGE && ulval == ULONG_MAX) /* out of range */
		goto cleanup;
	if (ulval > INT_MAX)
		goto cleanup;
	status = (int)ulval;

	success = 1;

	if (tdiff_p != NULL) {
		/* the caller want to know how much time the request took */
		timersub(&t2, &t1, tdiff_p);
	}

	/* FALLTHROUGH */
cleanup:
	(void)close(s);
	free(req);
	free(path);
	free(hex);
	return (success ? status : -1);
}
