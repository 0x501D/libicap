AC_PREREQ([2.69])
AC_INIT([libicap], [0.0.1-RC0])
AC_CONFIG_MACRO_DIR([m4])
ACX_DEBUG_CFLAGS
AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([src/config.h])
AM_INIT_AUTOMAKE([foreign 1.16])

# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
ICAP_LIBRARY_VERSION=0:0:0
AC_SUBST(ICAP_LIBRARY_VERSION)

AC_PROG_LIBTOOL
AC_LANG_C
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_INSTALL

AC_CHECK_HEADERS([stdint.h])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 libicap.pc
                 ])
AC_OUTPUT
