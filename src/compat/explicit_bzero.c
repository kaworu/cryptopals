/*
 * compat/explicit_bzero.c
 *
 * see https://www.cryptologie.net/article/419/zeroing-memory-compiler-optimizations-and-memset_s/
 */
#include "compat.h"


void
explicit_bzero(void *buf, size_t len)
{
	volatile unsigned char *p = buf;
	while (len > 0) {
		*p++ = 0;
		len--;
	}
}
