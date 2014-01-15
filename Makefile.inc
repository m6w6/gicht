AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -D_REENTRANT
AM_CFLAGS = $(PTHREAD_CFLAGS) $(DEBUG_CFLAGS)
LDADD = $(PTHREAD_LIBS)
