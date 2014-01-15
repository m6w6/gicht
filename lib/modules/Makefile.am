include ../../Makefile.inc

pkglib_LTLIBRARIES = echo.la
AM_LDFLAGS = -module -shared -avoid-version

echo_la_SOURCES = echo.c
echo_la_LIBADD = ../daemon/libgichtd.la

if WITH_LEVELDB
pkglib_LTLIBRARIES += leveldb.la
leveldb_la_SOURCES = leveldb.c
leveldb_la_LIBADD = ../daemon/libgichtd.la -lleveldb
endif

if WITH_OPENSSL
pkglib_LTLIBRARIES += ssl.la
ssl_la_SOURCES = ssl.c
ssl_la_LIBADD = ../daemon/libgichtd.la -lssl
endif

if WITH_GSASL
pkglib_LTLIBRARIES += gsasl.la
gsasl_la_SOURCES = gsasl.c
gsasl_la_LIBADD = ../daemon/libgichtd.la -lgsasl
endif
