#ifdef SunOS
#include <security/pam_appl.h>
#endif
#include <security/pam_modules.h>
#include <unistd.h>
#include <rpcsvc/ypclnt.h>
#include <stdlib.h>
#include <pwd.h>
#include "logging.h"
#include "constants.h"
#include "util.h"

/* Will this be shared between all instances of the module? */
static int debug=0;
static int gdb=0; 

int
getHomeDir(char *user, char *homeDir)
{
  int result=PAM_SUCCESS;
  struct passwd *p;
  NOTNULL(user);
  NOTNULL(homeDir);
  p = getpwnam(user);
  NOTNULL(p);
  NOTNULL(p->pw_dir);
  strcpy(homeDir,p->pw_dir);
  return result;
}

int 
getUID(char *user)
{
  struct passwd *p;

  if (user == NULL || *user == 0) {
    return 0;
  }
  if (*user >= '0' && *user <= '9') {
    return atoi(user);
  }
  p = getpwnam(user);
  if (p == NULL) {
    return 0;
  } else {
    return p->pw_uid;
  }
}

int
isDebuggingOn()
{
  return (debug!=0);
}

void
turnOnDebugging()
{
  debug=1;
}

int
isGdbEnabled()
{
  return (gdb!=0);
}

void
enableGdb()
{
  gdb=1;
}

void
cookService(char *service, char *cookedService)
{
  if ((strcmp(service,"dtlogin")==0) ||
      (strcmp(service,"gdm")==0) ||
      (strcmp(service,"kdm")==0)) 
    {
      strcpy(cookedService,"xdm");
    } else {
      strcpy(cookedService,service);
    }
}

int
sessid(char *tty, char *id)
{
  int result=PAM_SUCCESS;
  char sessbuf[512];
  char *p, tty0[512];

  DEBUG("Generating sessid...");
  if( !tty || tty[0] == 0 ) {
    snprintf(tty0, 512, "%d", (int)getpid());
  } else {
    strncpy(tty0, tty, 512);
  }
  if (gethostname(sessbuf, sizeof(sessbuf)) == 0) {
    p = sessbuf; 
    while (*p != 0 && *p != '.') { 
      p++; 
    };
    *p = 0;
    strncat(sessbuf, ":", 512); 
    strncat(sessbuf, tty0, 512);
  } else {
    strncpy(sessbuf, tty0, 512);
  }
  DEBUG("Generated sessid: %s",sessbuf);
  strcpy(id,sessbuf);
  return result;
}

int
getDisplay(char *tty, char *rhost, char *service, char *display)
{
  int result=PAM_SUCCESS;
  if (strcmp(service,"dtlogin") != 0) {
    strcpy(display,tty);
  } else /* dtlogin */ {
/*      char *DISPLAY=getenv("DISPLAY"); */
/*      NOTNULL(DISPLAY); */
/*      DEBUG("DISPLAY=%s",DISPLAY); */
/*      strcpy(display,DISPLAY); */
    NOTNULL(rhost);
    strcpy(display,rhost);
    DEBUG("display=%s",display);
  }
  return result;
}

int
cookDisplay(char *tty, char *from)
{
  int result=PAM_SUCCESS;
  char tmp[RANDOM_LENGTH];
  NOTNULL(tty);
  NOTNULL(from);
  result=cut(tty,':',1,from);
  DEBUG("cut field 1 from '%s' with delimiter ':' yielded '%s'", tty, from);
  ASSERT;
  if (strcmp(from,tty)==0 || strcmp(from,"")==0) {
    char hostname[RANDOM_LENGTH];
    if (gethostname(hostname,RANDOM_LENGTH)!=0) {
      PERROR("gethostname failed");
      result=PAM_SESSION_ERR;
      return result;
    }
    DEBUG("got hostname '%s'", hostname);
    strcpy(from,hostname);
    strcpy(tmp,hostname);
    strcat(tmp,tty);
    strcpy(tty,tmp);
  }
  return result;
}

int
getLocation(char *rhost, char *location)
{
  int result=PAM_SUCCESS;
  char *nisDomain;
  char *val;
  int len;
  int yperr;
  NOTNULL(rhost);
  NOTNULL(location);
  // Try ypprot_err(yperr) if you get meaningless errors
  yperr=yp_get_default_domain(&nisDomain);
  YP_ASSERT;
  DEBUG("Got NIS domain '%s'",nisDomain);
  yperr=yp_match(nisDomain,
		 "labterm",
		 rhost,
		 strlen(rhost),
		 &val,
		 &len);
  YP_ASSERT;
  NOTNULL(val);
  DEBUG("Got value '%s' for key '%s'",val,rhost);
  NONZERO(len);
  result=cut(val,' ',2,location);
  ASSERT;
  result=stripCRLF(location);
  ASSERT;
  return result;
}

int
stripCRLF(char *s)
{
  int result=PAM_SUCCESS;
  int len;
  NOTNULL(s);
  len=strlen(s);
  DEBUG("last byte of '%s' has value '%d'",s,s[len-1]);
  if (s[len-1] == '\n') {
    DEBUG("stripping CRLF from '%s'",s);
    s[len-1] = '\0';
  }
  return result;
}
  
/**
 *
 * If the delimiter does not appear, make target empty
 * If the field index is too big, make target empty
 * Otherwise, copy the field into target
 *
 */
int
cut(char *source,char delimiter,int field,char *target)
{
  int result=PAM_SUCCESS;
  int fieldCount=1;
  int i=0;
  int j=0;
  NOTNULL(source);
  NOTNULL(target);
  target[j]='\0';
  while ((source[i] != '\0') && (fieldCount <= field)) {
    if (source[i] == delimiter) {
      fieldCount++;
      i++;
      continue;
    }
    if (fieldCount == field) {
      target[j++]=source[i++];
    } else {
      i++;
    }
  }
  target[j]='\0';
  return result;
}
