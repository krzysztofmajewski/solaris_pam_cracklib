#ifndef PAM_MODULE_H
#define PAM_MODULE_H

/**
 * A generic interface for PAM modules
 *
 */

#ifdef SunOS
#include <security/pam_appl.h>
#endif
#include <security/pam_modules.h>

#ifdef Linux
#define LOG_FACILITY LOG_AUTHPRIV
#else
#define LOG_FACILITY LOG_AUTH
#endif

#define PAM_GET_ITEM(pam_handle, key, valuep) _pamGetItem(pam_handle, key, #key, valuep)

#define PAM_SET_ITEM(pam_handle, key, val) _pamSetItem(pam_handle, key, #key, val)

int
_pamGetItem(pam_handle_t *pamh, int key, const char *keyName, void **valuep);

int
_pamSetItem(pam_handle_t *pamh, int key, const char *keyName, const void *val);

int
getArg(int argc, const char **argv, const char *key, void **value);
  
int
pamErrorMessage(pam_handle_t *pamh, 
#ifdef Linux
		const char *message
#else
		char *message
#endif
		);

int
pamInfoMessage(pam_handle_t *pamh, 
#ifdef Linux
		const char *message
#else
		char *message
#endif
		);

extern char *
getModuleName(pam_handle_t *pamh);

#endif
