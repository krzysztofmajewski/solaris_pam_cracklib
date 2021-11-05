#ifndef UTIL_H
#define UTIL_H

int
getHomeDir(char *user, char *homeDir);

int 
getUID(char *user);

int
isDebuggingOn();

void
turnOnDebugging();

int
isGdbEnabled();

void
enableGdb();

int
cut(char *source,char limiter,int field,char *target);

int
stripCRLF(char *s);

int
getDisplay(char *tty, char *rhost, char *service, char *display);

void
cookService(char *service, char *cookedService);

int
cookDisplay(char *tty, char *from);

int
getLocation(char *rhost, char *location);

int
sessid(char *tty, char *id);

#endif
