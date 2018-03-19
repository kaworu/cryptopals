#ifndef COMPAT_H
#define COMPAT_H
/*
 * compat.h
 *
 * Compatibility stuff.
 */

#if !defined(HAVE_EXPLICIT_BZERO)
#include "compat/explicit_bzero.h"
#endif

#endif /* ndef COMPAT_H */
