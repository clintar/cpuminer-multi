#
# $Id: Makefile,v 1.57 2005/06/13 16:34:53 evertonm Exp $
#

#DEBUG += -DRULI_SRV_DEBUG 
#DEBUG += -DRULI_HOST_DEBUG
#DEBUG += -DRULI_RES_DEBUG
#DEBUG += -DRULI_TXT_COMPARE_DEBUG
#DEBUG += -DRULI_SYNC_DEBUG
#DEBUG += -DRULI_SEARCH_DEBUG
#DEBUG += -DRULI_MSG_DUMP_DEBUG -DRULI_SOCK_DUMP_DEBUG
#DEBUG += -DRULI_SMTP_DEBUG
#DEBUG += -DRULI_RFC3484_DEBUG

#
# OOP_INCLUDE_DIR points the location of
# Liboop headers in your system
#
# Debian packaging likes this: OOP_BASE_DIR = /usr
#
OOP_BASE_DIR    = /usr/local/oop
OOP_INCLUDE_DIR = $(OOP_BASE_DIR)/include
OOP_LIB_DIR     = $(OOP_BASE_DIR)/lib

#
# INSTALL_BASE_DIR indicates where RULI
# is to be installed in your system
#
# Example: INSTALL_BASE_DIR=/usr/local/ruli
#
# Debian packaging likes this: INSTALL_BASE_DIR = $(DESTDIR)/usr
#
INSTALL_BASE_DIR     = ../install/ruli
INSTALL_INCLUDE_DIR  = $(INSTALL_BASE_DIR)/include
INSTALL_LIB_DIR      = $(INSTALL_BASE_DIR)/lib
INSTALL_MAN_DIR      = $(INSTALL_BASE_DIR)/share/man
INSTALL_MAN3_DIR     = $(INSTALL_MAN_DIR)/man3

# SunOS, Linux
PLATFORM=$(shell uname)

ifeq ($(PLATFORM),SunOS)
DEFINE_SOLARIS = -D_RULI_SOLARIS_
endif

WARN = -pedantic -ansi -Wshadow -Wpointer-arith -Wcast-qual \
	-Wcast-align -Wwrite-strings -Wredundant-decls
CC = gcc

# gcc-specific options (not valid for g++)
ifeq ($(CC),gcc)
WARN += -Wnested-externs
WARN += -Wmissing-prototypes
WARN += -Wstrict-prototypes
endif

SHARED = -fPIC
FLAGS = $(DEBUG) -O2 -pipe -Wall -g -shared -fPIC -D_REENTRANT \
        $(DEFINE_SOLARIS) -I. -I$(OOP_INCLUDE_DIR)
SOFT_CFLAGS = $(WARN) $(FLAGS)
CFLAGS = $(WARN) -Werror $(FLAGS)
LIBOBJ = ruli_isaac.o ruli_mem.o ruli_rand.o ruli_util.o ruli_list.o \
	ruli_addr.o ruli_sock.o ruli_txt.o ruli_msg.o ruli_fsm.o \
	ruli_res.o ruli_parse.o ruli_host.o ruli_srv.o ruli_conf.o \
	ruli_search.o ruli_http.o ruli_smtp.o ruli_sync.o \
	ruli_getaddrinfo.o
SHAREDOBJ = $(LIBOBJ:%.o=%.os)
SONAME = libruli.so.4
LDFLAGS = -L$(OOP_LIB_DIR)

COMPILE = $(CC) $(ARCH) $(CPPFLAGS) $(CFLAGS) -c
SHARED_COMPILE = $(CC) $(ARCH) $(CPPFLAGS) $(SHARED) $(CFLAGS) -o $@ -c

# no -Werror
SOFT_COMPILE = $(CC) $(ARCH) $(CPPFLAGS) $(SOFT_CFLAGS) -c
SHARED_SOFT_COMPILE = $(CC) $(ARCH) $(CPPFLAGS) $(SHARED) $(SOFT_CFLAGS) -o $@ -c

.PHONY: default
default: ruli

all: ruli

.PHONY: clean
clean:
	rm -f *~ .*~ *.o *.os *.so *.a *.so.*

.PHONY: build
build: clean default

.PHONY: strip
strip: ruli
	strip $(SONAME) libruli.a

.PHONY: install
install: ruli
	mkdir -p $(INSTALL_LIB_DIR) $(INSTALL_INCLUDE_DIR) $(INSTALL_MAN3_DIR)
	cp $(SONAME) libruli.a $(INSTALL_LIB_DIR)
	cp *.h $(INSTALL_INCLUDE_DIR)
	cp ../doc/man/*.3 $(INSTALL_MAN3_DIR)
	cd $(INSTALL_LIB_DIR) && ln -s $(SONAME) libruli.so
	@echo
	@echo "REMINDER:"
	@echo "Add $(INSTALL_LIB_DIR) to your dynamic loader path:"
	@echo "# echo $(INSTALL_LIB_DIR) >> /etc/ld.so.conf"
	@echo "# ldconfig"
	@echo

.PHONY: ruli
ruli: $(SONAME) libruli.a

#
# This "SOFT" section forces compiling of some
# source files without the -Werror options.
#

ruli_util.o: ruli_util.c ruli_util.h
	$(SOFT_COMPILE) $<

ruli_addr.o: ruli_addr.c ruli_addr.h
	$(SOFT_COMPILE) $<

ruli_sock.o: ruli_sock.c ruli_sock.h
	$(SOFT_COMPILE) $<

ruli_res.o: ruli_res.c ruli_res.h
	$(SOFT_COMPILE) $<

ruli_getaddrinfo.o: ruli_getaddrinfo.c ruli_getaddrinfo.h
	$(SOFT_COMPILE) $<

ruli_util.os: ruli_util.c ruli_util.h
	$(SHARED_SOFT_COMPILE) $<

ruli_addr.os: ruli_addr.c ruli_addr.h
	$(SHARED_SOFT_COMPILE) $<

ruli_sock.os: ruli_sock.c ruli_sock.h
	$(SHARED_SOFT_COMPILE) $<

ruli_res.os: ruli_res.c ruli_res.h
	$(SHARED_SOFT_COMPILE) $<

ruli_getaddrinfo.os: ruli_getaddrinfo.c ruli_getaddrinfo.h
	$(SHARED_SOFT_COMPILE) $<

#
# End of "SOFT" section
#

%.o: %.c %.h
	$(COMPILE) $<

%.os: %.c %.h
	$(SHARED_COMPILE) $<

libruli.so: $(SHAREDOBJ)
ifdef DEFINE_SOLARIS
	$(CC) $(ARCH) $(CFLAGS) $(LDFLAGS) -Wl,-h,$(SONAME) -o $@ \
		$(SHAREDOBJ) -loop -ldl -lsocket -lnsl
else
	$(CC) $(ARCH) $(CFLAGS) $(LDFLAGS) -Wl,-soname,$(SONAME) \
		-Wl,--version-script,libruli.ver -o $@ $(SHAREDOBJ) -loop -ldl
endif

$(SONAME): libruli.so
	cp libruli.so $(SONAME)

libruli.a: $(LIBOBJ) 
ifdef DEFINE_SOLARIS
	ar -r -v $@ $(LIBOBJ)
else
	ar rcv $@ $(LIBOBJ)
	ar sv $@
endif


