#ifndef COMPAT_STRLCPY_H
#define COMPAT_STRLCPY_H
/*
 * compat/strlcpy.h
 *
 * OpenBSD's strlcpy(3) and strlcat(3),
 *      consistent, safe, string copy and concatenation.
 */
#include <stddef.h>


size_t	strlcpy(char *dst, const char *src, size_t siz);

#endif /* ndef COMPAT_STRLCPY_H */
