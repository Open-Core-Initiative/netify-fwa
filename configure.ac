# Netify FWA Autoconf
# Copyright (C) 2018 eGloo Incorporated <http://www.egloo.ca>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_PREREQ([2.69])
AC_INIT([Netify FWA], [1.2.5],
    [https://gitlab.com/netify.ai/public/netify-fwa/issues],
    [netify-fwa], [http://www.netify.ai/])
AM_INIT_AUTOMAKE([1.9 tar-pax])
AC_CONFIG_SRCDIR([nfa_main.py])
AC_CONFIG_HEADERS([pf/config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_HOST

# Checks for programs.
AC_PROG_SED
PKG_PROG_PKG_CONFIG([0.23])
AC_PROG_CC
AM_PROG_LIBTOOL
AC_PROG_INSTALL
AC_PATH_PROG([osc], [osc])
AM_CONDITIONAL([HAVE_OSC], [test x$osc != x])

case "${host_os}" in
    freebsd*)
        PKG_CHECK_MODULES([PYTHON36], [python-3.6])
        AM_CONDITIONAL(USE_PF, true)
        ;;
    *)
        AM_CONDITIONAL(USE_PF, false)
        ;;
esac

# Parameters: --with/without
AC_ARG_WITH([systemdsystemunitdir],
     [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files])],,
     [with_systemdsystemunitdir=auto])
AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"], [
     def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)

     AS_IF([test "x$def_systemdsystemunitdir" = "x"],
   [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
    [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
    with_systemdsystemunitdir=no],
   [with_systemdsystemunitdir="$def_systemdsystemunitdir"])])
AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
      [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])

AC_ARG_WITH([tmpfilesdir],
     [AS_HELP_STRING([--with-tmpfilesdir=DIR], [Directory for systemd tmpfiles configuration])],,
     [with_tmpfilesdir=auto])

AS_IF([test "x$with_tmpfilesdir" = "xyes" -o "x$with_tmpfilesdir" = "xauto"], [
     def_tmpfilesdir=$($PKG_CONFIG --variable=tmpfilesdir systemd)
     AS_IF([test "x$def_tmpfilesdir" = "x"],
   [AS_IF([test "x$with_tmpfilesdir" = "xyes"],
    [AC_MSG_ERROR([tmpfiles support requested but pkg-config unable to query systemd package])])
    with_tmpfilesdir=no],
   [with_tmpfilesdir="$def_tmpfilesdir"])])
AS_IF([test "x$with_tmpfilesdir" != "xno"],
      [AC_SUBST([tmpfilesdir], [$with_tmpfilesdir])])

# Convenience substitutions
AC_SUBST([persistentstatedir], [$sysconfdir/netify-fwa])
AC_SUBST([volatilestatedir], [$localstatedir/run/$PACKAGE_TARNAME])

AC_CONFIG_FILES([Makefile deploy/Makefile deploy/rpm/netify-fwa.spec \
    pf/Makefile deploy/pfsense/Makefile deploy/systemd/Makefile \
    deploy/debian/Makefile])

AC_OUTPUT
