#ifndef PAM_PASSWORD_H
#define PAM_PASSWORD_H

/**
 * A generic interface for PAM modules of the "password" type
 *
 */

#ifdef SunOS
#include <security/pam_appl.h>
#endif
#include <security/pam_modules.h>

#include "pam_module.h"

extern int
changeAuthorizationTokens(pam_handle_t *pamh, int flags);

#endif
