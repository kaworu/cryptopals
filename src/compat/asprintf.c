/*
 * asprintf.c
 *
 * à-la FreeBSD asprintf(3).
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "compat.h"


int
asprintf(char **s_p, const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vasprintf(s_p, fmt, ap);
	va_end(ap);

	return ret;
}


int
vasprintf(char **s_p, const char *fmt, va_list ap)
{
	int len = -1;
	size_t size = 0;
	char *s = NULL;
	va_list cpy;
	int ret = -1;

	va_copy(cpy, ap);
	len = vsnprintf(NULL, 0, fmt, ap);
	if (len == -1)
		goto cleanup;
	/* one additional character for the terminating NUL. */
	size = (size_t)len + 1;

	s = malloc(size);
	if (s == NULL) {
		/* set s_p to NULL, as FreeBSD does */
		*s_p = NULL;
		errno = ENOMEM;
		goto cleanup;
	}

	ret = vsnprintf(s, size, fmt, cpy);
	if (ret == -1) {
		/* set s_p to NULL, as FreeBSD does */
		*s_p = NULL;
		errno = ENOMEM;
		goto cleanup;
	}
	/* NUL-terminated the result string */
	s[len] = '\0';

	*s_p = s;
	s = NULL;

	/* FALLTHROUGH */
cleanup:
	free(s);
	va_end(cpy);
	return ret;
}
