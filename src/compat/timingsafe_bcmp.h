#ifndef COMPAT_TIMINGSAFE_BCMP_H
#define COMPAT_TIMINGSAFE_BCMP_H
/*
 * compat/timingsafe_bcmp.h
 *
 * à-la OpenBSD timingsafe_bcmp(3).
 */
#include <stddef.h>


int	timingsafe_bcmp(const void *b1, const void *b2, size_t n);

#endif /* ndef COMPAT_TIMINGSAFE_BCMP_H */
