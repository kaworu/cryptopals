#ifndef ASPRINTF_H
#define ASPRINTF_H
/*
 * asprintf.h
 *
 * à-la FreeBSD asprintf(3).
 */
#include <stdarg.h>


int	asprintf(char **str_p, const char *fmt, ...);
int	vasprintf(char **str_p, const char *fmt, va_list ap);

#endif /* ndef ASPRINTF_H */
