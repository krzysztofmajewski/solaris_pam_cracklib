#ifndef LOGGING_H
#define LOGGING_H

#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#ifdef SunOS
#include <security/pam_appl.h>
#endif
#include <security/pam_modules.h>
#include "constants.h"
#include "util.h"

#ifndef YPERR_SUCCESS
#define YPERR_SUCCESS 0
#endif

#define DEBUG(format, ...)  if (isDebuggingOn()) syslog(LOG_DEBUG, "[%s:%d] " format, __FILE__, __LINE__ , ## __VA_ARGS__)
#define ERROR(format, ...) syslog(LOG_ERR , "[%s:%d] " format, __FILE__, __LINE__ , ## __VA_ARGS__)
#define PERROR(format, ...) _perror("[%s:%d] " format, __FILE__, __LINE__ , ## __VA_ARGS__)
#define PAM_ERROR(errnum)  _error(pamh, errnum, __FILE__, __LINE__)
#define ASSERT if (result != PAM_SUCCESS) {return result;}
#define NOTNULL(x) if (x == NULL) {syslog(LOG_ERR,"[%s:%d] Unexpected NULL pointer", __FILE__, __LINE__); result=PAM_AUTHTOK_ERR; return result;}
#define NONZERO(x) if (x == 0) {syslog(LOG_ERR,"[%s:%d] Unexpected zero value", __FILE__, __LINE__); result=PAM_AUTHTOK_ERR; return result;}
#define NOT_IMPLEMENTED syslog(LOG_ERR,"[%s:%d] Not implemented yet", __FILE__ , __LINE__); result=PAM_AUTHTOK_ERR; return result;
#define YP_ASSERT if (yperr != YPERR_SUCCESS) {syslog(LOG_ERR,"[%s:%d] ypclnt error (%s)", __FILE__, __LINE__, yperr_string(yperr)); result=PAM_AUTHTOK_ERR; return result;}

void
_perror(char *format, ...);

void
_error(pam_handle_t *pamh, int errnum, char *file, int line);

#endif
