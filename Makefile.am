
if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

RULI_INCLUDES= -I$(top_srcdir)/compat/ruli/src

EXTRA_DIST	= example-cfg.json nomacro.pl

SUBDIRS		= compat compat/ruli/src

INCLUDES	= $(PTHREAD_FLAGS) -fno-strict-aliasing $(JANSSON_INCLUDES) $(RULI_INCLUDES)

bin_PROGRAMS	= minerd

dist_man_MANS	= minerd.1

minerd_SOURCES	= elist.h \
		  miner.h \
		  compat.h \
		  cpu-miner.c \
		  util.c \
		  wildkeccak.c \
		  xmalloc.c

minerd_LDFLAGS	= $(PTHREAD_FLAGS) 
minerd_LDADD	= @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@ -loop compat/ruli/src/libruli.a
minerd_CPPFLAGS = @LIBCURL_CPPFLAGS@
minerd_CFLAGS   = -std=gnu11 -O3 -march=native -fPIC -flto

if HAVE_WINDOWS
minerd_CFLAGS += -Wl,--stack,10485760 -DCURL_STATICLIB
endif

if !HAVE_WINDOWS
minerd_LDFLAGS	+= -pie
#minerd_CFLAGS += 
endif
