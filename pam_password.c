/**
 *
 * Generic framework for a PAM module of the "password" type
 * (Perhaps not generic enough...)
 * Currently this object performs no authentication, nor does
 * it get or store authentication tokens in the passwd map.
 * You should ensure that these functions are performed by the rest
 * of your PAM stack.
 *
 */

/**
 *
 * TODO: 
 * - make sure syslog doesn't break application's logging
 *
 */
#define PAM_SM_PASSWORD

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include "logging.h"
#include "pam_password.h"
#include "util.h"
#include "constants.h"
#include "cracklib.h"

static void
_post(pam_handle_t *pamh,
      int result)
{
  if (result != PAM_SUCCESS) {
    PAM_ERROR(result);
  } else {
    DEBUG("Successfully changed authorization tokens.");
  }
  closelog();
}

static int
_pre(pam_handle_t *pamh,
     int flags,
     int argc,
     const char ** argv)
{
  int result=PAM_SUCCESS;
  char *const *envList = pam_getenvlist(pamh);
  int i;
  openlog(getModuleName(pamh),0,LOG_FACILITY);
  for (i=0; i<argc; i++) {
    if (strcmp("debug",argv[i])==0) {
      turnOnDebugging();
    } else if (strcmp("gdb",argv[i])==0) {
      enableGdb();
    } else if (strcmp("use_authtok",argv[i])) {
      ERROR("Unrecognized argument '%s'", argv[i]);
      ERROR("Check your /etc/pam.d/* or /etc/pam.conf");
      result=PAM_AUTHTOK_ERR;
      return result;
    }
  }
  //  DEBUG("Changing authorization tokens...");
  if (isGdbEnabled()) {
    // use syslog directly in case they haven't passed the "debug" flag
    syslog(LOG_DEBUG, "My PID is %d", getpid());
    syslog(LOG_DEBUG, "Waiting %d seconds for debugger...", GDB_WAIT);
    sleep(GDB_WAIT);
    syslog(LOG_DEBUG, "Done waiting.");
  }
  for (;*envList != NULL;envList++) {
    DEBUG("%s",*envList);
  }
  return result;
}

/**
 * 
 * Hook called by libPAM
 *
 */
#ifdef Linux
PAM_EXTERN 
#endif
int
pam_sm_chauthtok(pam_handle_t *pamh,
		 int flags,
		 int argc,
		 const char **argv)
{
  int result=PAM_SUCCESS;
  if (flags & PAM_PRELIM_CHECK) {
    char *oldpw = NULL;
    result = _pre(pamh, flags, argc, argv);
    DEBUG("called with flag PAM_PRELIM_CHECK");
    if (getArg(argc, argv, "use_authtok", NULL)) {
      result = PAM_GET_ITEM(pamh, PAM_OLDAUTHTOK, (void **)&oldpw);
      oldpw=NULL; // just checking if we can get it
      if (result != PAM_SUCCESS) {
	ERROR("Couldn't get item PAM_OLDAUTHTOK");
	return PAM_TRY_AGAIN;
      }
    } else {
      ERROR("You must supply the use_authtok argument for now");
      return PAM_AUTHTOK_ERR;
    }
  } else if (flags & PAM_UPDATE_AUTHTOK) {
    char *newpw = NULL;
    char pw[9];
    DEBUG("called with flag PAM_UPDATE_AUTHTOK");    
    if (getArg(argc, argv, "use_authtok", NULL)) {
      result = PAM_GET_ITEM(pamh, PAM_AUTHTOK, (void **)&newpw);
      if (result != PAM_SUCCESS) {
	ERROR("Couldn't get item PAM_AUTHTOK");
	return result;
      }
    } else {
      ERROR("You must supply the use_authtok argument for now");
      return PAM_AUTHTOK_ERR;
    }
    NOTNULL(newpw);
    strncpy(pw,newpw,8); // our NIS only does 8-character passwords
    pw[8]='\0';
    if (!crack(pamh,pw)) {
      PAM_SET_ITEM(pamh, PAM_AUTHTOK, pw);
      //      PAM_SET_ITEM(pamh, PAM_REPOSITORY, "nis"); //segfaults
    } else {
      result=PAM_AUTHTOK_ERR;
    }
    memset(pw,0,8);
    newpw=NULL;
    _post(pamh,result);
    DEBUG("PAM result = %d\n", result);
  } else {
    ERROR("bad flags: %d\n", flags);
    result = PAM_SERVICE_ERR;
  }
  return result;
}
