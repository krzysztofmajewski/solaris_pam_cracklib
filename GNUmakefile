# !!! Hello !!!
# Make sure you are using GNU Make, and not some cheap imitation.
# !!! Thank you !!!

OS=$(shell uname)
ARCH=$(shell uname -p)
CRACKLIB_TARGET=pam_cracklib.so
DESTDIR=/usr/opt/lib/security
PERMS=0700
PASSWORD_SRCS=pam_password.c
COMMON_SRCS=pam_module.c logging.c util.c
CRACKLIB_SRCS=cracklib.c $(COMMON_SRCS) $(PASSWORD_SRCS)
CRACKLIB_OBJS=$(CRACKLIB_SRCS:.c=.o)
DICTPATH="/usr/opt/cracklib/pw_dict"
INCL=
LIBS=-lpam
CRACK_LIBS=-lcrack
CC=gcc
CFLAGS=-g -Wall -fPIC -D$(OS) -D$(ARCH)
LD=ld
ifeq ($(OS),SunOS) 
LDFLAGS=-G -z redlocsym -L/usr/opt/lib -R/usr/opt/lib
else
LDFLAGS=-x --shared -L/usr/opt/lib -R/usr/opt/lib
endif
RM=rm
FORCE_REBUILD=

password:	$(CRACKLIB_TARGET)

# We will use this when cproto(1) stops sucking
# %.h : %.c $(FORCE_REBUILD) # A ".o" file depends on the corresponding ".c" file
# 	cproto -E 0 $< 

%.o : %.c $(FORCE_REBUILD) # A ".o" file depends on the corresponding ".c" file
	$(CC) $(INCL) $(CFLAGS) -c $< -o $@ 

% : %.o # override default linking rule just in case
	@echo
	@echo $@ is not a valid target
	@echo

$(CRACKLIB_TARGET) : CFLAGS += -DMODULE_NAME=\"$(CRACKLIB_TARGET)\"  -DCRACKLIB_DICTPATH=\"$(DICTPATH)\"
$(CRACKLIB_TARGET) : $(FORCE_REBUILD) $(CRACKLIB_OBJS)
	$(LD) $(LDFLAGS) -o $@ $(CRACKLIB_OBJS) $(LIBS) $(CRACK_LIBS)
	@echo
	@echo $@ built successfully!
	@echo

# Need -O so the inline "stat()" gets compiled, grr
$(DESTDIR)/$(CRACKLIB_TARGET) : $(CRACKLIB_TARGET)
	@echo installing...
	test -d $(DESTDIR) || mkdir -p $(DESTDIR)
	cp $(CRACKLIB_TARGET) $(DESTDIR)
	chown root $(DESTDIR)/$(CRACKLIB_TARGET)
	chgrp root $(DESTDIR)/$(CRACKLIB_TARGET)
	chmod $(PERMS) $(DESTDIR)/$(CRACKLIB_TARGET)

$(FORCE_REBUILD):
	@echo rebuilding...

install: $(DESTDIR)/$(CRACKLIB_TARGET)

rebuild:
	$(MAKE) $(MOREMAKEFLAGS) "FORCE_REBUILD=REBUILD"

clean:
	$(RM) -f $(CRACKLIB_TARGET)
	$(RM) -f $(CRACKLIB_OBJS)
	$(RM) -f #*
	$(RM) -f *~
