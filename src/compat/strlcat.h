#ifndef COMPAT_STRLCAT_H
#define COMPAT_STRLCAT_H
/*
 * compat/strlcat.h
 *
 * OpenBSD's strlcpy(3) and strlcat(3),
 *      consistent, safe, string copy and concatenation.
 */
#include <stddef.h>


size_t	strlcat(char *dst, const char *src, size_t siz);

#endif /* ndef COMPAT_STRLCAT_H */
