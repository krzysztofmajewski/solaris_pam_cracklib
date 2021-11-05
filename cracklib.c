/**
 * Run Alec Muffett's cracklib on a putative new password
 * Unlike the original pam_cracklib, this is intended to build on Sun machines
 *
 */

#include "/usr/opt/include/packer.h"
#include "pam_password.h"
#include "logging.h"
#include "util.h"
#include "cracklib.h"

#ifdef MODULE_NAME
char *_moduleName=MODULE_NAME;
#else
#error "You must define MODULE_NAME"
#endif

char *
getModuleName(pam_handle_t *pamh)
{
  return _moduleName;
}

int
crack(pam_handle_t *pamh, const char *pw)
{
  int result=1;
  const char *msg=NULL;
  //  chop(pw);
  msg=FascistCheck(pw,CRACKLIB_DICTPATH);
  if (msg) {
    char sorry[RANDOM_LENGTH];
    strncpy(sorry,
	    "Your new password was rejected for the following reason:\n",
	    RANDOM_LENGTH);
    strncat(sorry, msg, RANDOM_LENGTH);
    pamErrorMessage(pamh, sorry);
  } else {
    result = 0;
    pamInfoMessage(pamh, "New password OK");
  }
  return result;
}
