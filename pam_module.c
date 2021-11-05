/**
 *
 * Generic framework for a PAM module 
 *
 */

/**
 *
 * TODO: 
 * - make sure syslog doesn't break application's logging
 *
 */

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include "logging.h"
#include "pam_module.h"
#include "util.h"
#include "constants.h"

static const char *_cookedService = NULL;

static void
_setCookedService(pam_handle_t *pamh)
{
  char service[RANDOM_LENGTH];
  static char cookedService[RANDOM_LENGTH];
  PAM_GET_ITEM(pamh,PAM_SERVICE,(void **)(&service));
  cookService(service,cookedService);
  _cookedService = cookedService;
}

static int
_hasGui(pam_handle_t *pamh)
{
  int result = 0;
  if (_cookedService == NULL) {
    _setCookedService(pamh);
  }
  result = !strncmp(_cookedService,"xdm",RANDOM_LENGTH);
  return result;
}

/**
 *
 *  This function should be called via the PAM_GET_ITEM macro.
 *
 *  Possible keys are:
 *      PAM_SERVICE (eg "sshd")  
 *      PAM_USER (eg "majewski")  
 *      PAM_USER_PROMPT  
 *      PAM_TTY (eg "/dev/pts/1") 
 *      PAM_RUSER  
 *      PAM_RHOST (eg "okocim.cs.ubc.ca") 
 *      PAM_CONV 
 *      PAM_FAIL_DELAY 
 *
 */
int
_pamGetItem(pam_handle_t *pamh, int key, const char *keyName, void **valuep)
{
  int result;
  NOTNULL(valuep);
  result = pam_get_item(pamh, key,
#ifdef Linux
			(const void **)
#else
			(void **)
#endif			
			valuep);
  if (result != PAM_SUCCESS) {
    PAM_ERROR(result);
    *valuep = NULL;
  } else if (*valuep == NULL) {
    result=PAM_SESSION_ERR;
    DEBUG("No value found for key '%s'", keyName);
  } else {
    if ( (key != PAM_AUTHTOK) && (key != PAM_OLDAUTHTOK)) {
      DEBUG("Found value '%s' for key '%s'", (char *)(*valuep), keyName);
    } else {
      int len,i;
      char xxx[RANDOM_LENGTH+1];
      len=strlen((char*)(*valuep));
      for(i=0;(i<RANDOM_LENGTH) && (i<len);i++){
	xxx[i]='x';
      }
      xxx[i]='\0';
      DEBUG("Found value '%s' for key '%s'", xxx, keyName);
    }
  }
  return result;
}

int
_pamSetItem(pam_handle_t *pamh, int key, const char *keyName, const void *val)
{
  int result;
  char *sanity = NULL;
  if ( (key != PAM_AUTHTOK) && (key != PAM_OLDAUTHTOK)) {  
    DEBUG("setting '%s' to '%s'", keyName, (char *)val);
  } else {
    int len,i;
    char xxx[RANDOM_LENGTH+1];
    NOTNULL(val);
    len=strlen((char*)val);
    for(i=0;(i<RANDOM_LENGTH) && (i<len);i++){
      xxx[i]='x';
    }
    xxx[i]='\0';
    DEBUG("setting '%s' to '%s'", keyName, xxx);
  }
  result = pam_set_item(pamh, key,
#ifdef Linux
			(const void *)
#else
			(void *)
#endif
			val);
  result = pam_get_item(pamh,key,(void **)&sanity);
  if ((sanity == NULL) || (strncmp(sanity,(char *)val,RANDOM_LENGTH))) {
    ERROR("sanity check failed");
  }
  sanity=NULL;
  if (result != PAM_SUCCESS) {
    PAM_ERROR(result);
  }
  return result;
}
    
static int 
_pamMessage(pam_handle_t *pamh, 
#ifdef Linux
	    const char *message,
#else
	    char *message,
#endif
	    int style);

int
pamErrorMessage(pam_handle_t *pamh, 
#ifdef Linux
		const char *message
#else
		char *message
#endif
		)
{
  return _pamMessage(pamh,message,PAM_ERROR_MSG);
}

int
pamInfoMessage(pam_handle_t *pamh, 
#ifdef Linux
		const char *message
#else
		char *message
#endif
	       )
{
  return _pamMessage(pamh,message,PAM_TEXT_INFO);
}

int
_pamMessage(pam_handle_t *pamh, 
#ifdef Linux
	    const char *message,
#else
	    char *message,
#endif
	    int style)
{
  typedef struct pam_message PAM_MESSAGE;
  typedef struct pam_response PAM_RESPONSE;
  int result=PAM_SUCCESS;
  struct pam_conv *pamConv=NULL;
  PAM_MESSAGE pamMessage; 
  PAM_MESSAGE **messages;
  PAM_RESPONSE *pamResponses; 

  NOTNULL(message);
  result=PAM_GET_ITEM(pamh,PAM_CONV,(void **)&pamConv);
  if (result != PAM_SUCCESS) {
    ERROR("Couldn't get item PAM_CONV");
  }
  NOTNULL(pamConv);
  NOTNULL(pamConv->conv);
  pamMessage.msg_style=style;
  pamMessage.msg=message;
  messages = calloc(1,sizeof(PAM_MESSAGE *)); 
  if (messages == NULL) {
    PERROR("calloc failed");
    result = PAM_SESSION_ERR;
    return result;
  }
  messages[0]=&pamMessage;
  DEBUG("sending message to application: '%s'", messages[0]->msg);
  result=pamConv->conv(1, 
#ifdef Linux
		       /* unnecessary cast: gcc bug or programmer brain bug? */
  		       (const PAM_MESSAGE **)messages,
#else
		       messages,
#endif
		       &pamResponses, 
		       NULL);
  if (result != PAM_SUCCESS) {
    PAM_ERROR(result);
  } else {
    /* give them time to read the message if need be*/
    if (_hasGui(pamh)) {
      int seconds = (style==PAM_ERROR_MSG) ? ERROR_WAIT : INFO_WAIT;
      DEBUG("sleeping for %d seconds...", seconds);
      sleep(seconds);
    }
  }
  if (pamResponses != NULL) {
    free(pamResponses);
  }
  free(messages);
  return result;
}

int
getArg(int argc, const char **argv, const char *key, void **value)
{
  int i;
  int result=0;
  NOTNULL(key);
  NOTNULL(argv);
  for (i=0; i<argc; i++) {
    const char *arg = argv[i];
    int keyLength = strlen(key);
    int argLength = strlen(arg);
    // holy buffer overflow, batman
    if (!strncmp(key,arg,keyLength)) {
      result=1;
      if ((argLength > keyLength) && (arg[keyLength] == '=')) {
	if (value) {
	  NOTNULL(*value);
	  strncpy(*value, arg+keyLength+1, argLength-keyLength-1);
	  strcpy((*value)+argLength-keyLength-1,"\0");
	}
      }
      break;
    }
  }
  return result;
}
