#include "varargs.h"
#include "logging.h"

void
_perror(char *format, ...)
{
  VA_LIST ap;
  int _errno = errno;
  const char *errorString=strerror(_errno);
  char syslogString[RANDOM_LENGTH]; // Why C sucks
  char suffix[RANDOM_LENGTH];
  char valueAddedFormat[RANDOM_LENGTH];

  VA_START(ap,format);
  sprintf(suffix, " (%s)", errorString?errorString:"Unknown error");
  strcpy(valueAddedFormat, format);
  strcat(valueAddedFormat, suffix);
  vsprintf(syslogString, valueAddedFormat, ap); 
  syslog(LOG_ERR, syslogString);
  VA_END(ap);
}

void
_error(pam_handle_t *pamh, int errnum, char *file, int line)
{
  const char *errorString=pam_strerror(pamh,errnum);
  char syslogString[RANDOM_LENGTH]; // Why C sucks

  sprintf(syslogString,
	  "[%s:%d] %s", 
	  file, 
	  line, 
	  errorString?errorString:"Unknown PAM error");
}
