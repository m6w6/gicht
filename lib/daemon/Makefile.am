include ../../Makefile.inc

lib_LTLIBRARIES = libgichtd.la
libgichtd_la_SOURCES = \
	acceptor.c \
	gichtd.c \
	module.c \
	options.c \
	worker.c

libgichtd_la_LIBADD = ../libgicht.la
libgichtd_la_LDFLAGS = -version-info $(VERSION_INFO)
