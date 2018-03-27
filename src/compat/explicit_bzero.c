/*
 * compat/explicit_bzero.c
 *
 * à-la OpenBSD explicit_bzero(3).
 */
#include "compat.h"


void
explicit_bzero(void *ptr, size_t size)
{
	(void)explicit_memset(ptr, 0, size);
}
