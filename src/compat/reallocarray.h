#ifndef COMPAT_REALLOCARRAY_H
#define COMPAT_REALLOCARRAY_H
/*
 * compat/reallocarray.h
 *
 * à-la OpenBSD reallocarray(3).
 */
#include <stddef.h>


void	*reallocarray(void *optr, size_t nmemb, size_t size);

#endif /* ndef COMPAT_REALLOCARRAY_H */
