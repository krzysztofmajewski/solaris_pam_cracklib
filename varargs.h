#ifndef VARARGS_H
#define VARARGS_H

#ifdef SunOS

#ifdef i386
#include <stdarg.h>
#define VA_LIST va_list
#define VA_START(valist,first) va_start(valist,first)
#define VA_ARG(valist,type) va_arg(valist,type)
#define VA_END(valist) va_end(valist)
#else
#include <sys/varargs.h>
#define VA_LIST va_list
#define VA_START(valist,first) va_start(valist,first)
#define VA_ARG(valist,type) va_arg(valist,type)
#define VA_END(valist) va_end(valist)
#endif

#else
#include <stdarg.h>
#define VA_LIST va_list
#define VA_START(valist,first) va_start(valist,first)
#define VA_ARG(valist,type) va_arg(valist,type)
#define VA_END(valist) va_end(valist)
#endif

#endif
