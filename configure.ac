#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.69])

# our own version constants
m4_define([VERSION_MAJOR], [1])
m4_define([VERSION_MINOR], [0])
m4_define([VERSION_PATCH], [0])
m4_define([VERSION_STATE], [dev])

m4_define([VERSION_FULL],
	[VERSION_MAJOR.VERSION_MINOR.VERSION_PATCH-VERSION_STATE])

AC_INIT([gicht], m4_defn([VERSION_FULL]), [mike@php.net])

AC_CONFIG_AUX_DIR([.])
AC_CONFIG_SRCDIR([src/gichtd.c])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([-Wall foreign check-news no-define])
AM_SILENT_RULES([yes])

AC_SUBST([GICHT_VERSION_MAJOR], [VERSION_MAJOR])
AC_SUBST([GICHT_VERSION_MINOR], [VERSION_MINOR])
AC_SUBST([GICHT_VERSION_PATCH], [VERSION_PATCH])
AC_SUBST([GICHT_VERSION_STATE], [VERSION_STATE])

# *** library versioning
# See: https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
# If the library source code has changed at all since the last update, 
# then increment revision (‘c:r:a’ becomes ‘c:r+1:a’).
# If any interfaces have been added, removed, or changed since the last update, 
# increment current, and set revision to 0.
# If any interfaces have been added since the last public release, then increment age.
# If any interfaces have been removed or changed since the last public release, 
# then set age to 0.
AC_SUBST([VERSION_INFO], [0:0:0])

ACX_DEBUG_CFLAGS

AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_AR
AC_PROG_INSTALL
AC_PROG_LIBTOOL

AC_CHECK_HEADER_STDBOOL
AC_CHECK_HEADERS([\
	errno.h\
	stdbool.h\
	signal.h\
	netdb.h\
	getopt.h\
	search.h\
	pthread.h\
	arpa/inet.h\
	netinet/in.h\
	sys/socket.h\
	sys/select.h\
	sys/time.h\
	sys/param.h\
])

AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_CHECK_DECL([MSG_NOSIGNAL], [ ], [
	AC_DEFINE([HAVE_MSG_NOSIGNAL], [1], [have MSG_NOSIGNAL])
], [
#include <sys/socket.h>
])

AC_CHECK_FUNCS([accept4])

AC_CHECK_HEADER([ev.h], [
	AC_DEFINE([HAVE_EV_H], [1], [libev ev.h])
], [
	AC_MSG_ERROR([ev.h of libev missing in $INCLUDES])
])

AC_CHECK_LIB([ev], [ev_default_loop])

ACX_PTHREAD

LT_INIT([dlopen pic-only])
LT_LIB_DLLOAD
LT_FUNC_DLSYM_USCORE
LT_SYS_DLSEARCH_PATH
LT_SYS_MODULE_EXT

AC_ARG_WITH([openssl], AS_HELP_STRING([--with-openssl], [build openssl module]), [], [with_openssl=check])
AS_IF([test "$with_openssl" != "no"], [
	AC_CHECK_HEADER([openssl/ssl.h], [
		AC_DEFINE([HAVE_OPENSSL_SSL_H], [1], [openssl/ssl.h])
		AC_CHECK_LIB([ssl], [SSLv23_server_method], [
			HAVE_LIBSSL=1
			AC_DEFINE_UNQUOTED([HAVE_LIBSSL], [$HAVE_LIBSSL], [-lssl])
		])
	])
])
AC_SUBST([HAVE_LIBSSL])
AM_CONDITIONAL([WITH_OPENSSL], [test "$HAVE_LIBSSL"])

AC_ARG_WITH([gsasl], AS_HELP_STRING([--with-gsasl], [build gsasl module]), [], [with_gsasl=check])
AS_IF([test "$with_gsasl" != "no"], [
	AC_CHECK_HEADER([gsasl.h], [
		AC_DEFINE([HAVE_GSASL_H], [1], [gsasl.h])
		AC_CHECK_LIB([gsasl], [gsasl_init], [
			HAVE_LIBGSASL=1
			AC_DEFINE_UNQUOTED([HAVE_LIBGSASL], [$HAVE_LIBGSASL], [-lgsasl])
		])
	])
])
AC_SUBST([HAVE_LIBGSASL])
AM_CONDITIONAL([WITH_GSASL], [test "$HAVE_LIBSASL"])

AC_ARG_WITH([leveldb], AS_HELP_STRING([--with-leveldb], [build leveldb module]), [], [with_leveldb=check])
AS_IF([test "$with_leveldb" != "no"], [
	AC_CHECK_HEADER([leveldb/c.h], [
		AC_DEFINE([HAVE_LEVELDB_C_H], [1], [leveldb/c.h])
		AC_CHECK_LIB([leveldb], [leveldb_open], [
			HAVE_LIBLEVELDB=1
			AC_DEFINE_UNQUOTED([HAVE_LIBLEVELDB], [$HAVE_LIBLEVELDB], [-lleveldb])
		])
	])
])
AC_SUBST([HAVE_LIBLEVELDB])
AM_CONDITIONAL([WITH_LEVELDB], [test "$HAVE_LIBLEVELDB"])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile lib/Makefile lib/daemon/Makefile lib/modules/Makefile src/Makefile include/Makefile include/gicht_version.h])
AC_OUTPUT
