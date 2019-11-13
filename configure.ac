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
AC_INIT([Netify FWA], [1.2.0],
    [https://gitlab.com/netify.ai/public/netify-fwa/issues],
    [netify-fwa], [http://www.netify.ai/])
AM_INIT_AUTOMAKE([1.9 tar-pax])
AC_CONFIG_SRCDIR([nfa_main.py])

# Convience substitutions
AC_SUBST([persistentstatedir], [$sysconfdir/netify-fwa])
AC_SUBST([volatilestatedir], [$localstatedir/run/$PACKAGE_TARNAME])

AC_CONFIG_FILES([Makefile deploy/Makefile deploy/rpm/netify-fwa.spec \
    deploy/systemd/netify-fwa.service deploy/systemd/netify-fwa.tmpf])

AC_OUTPUT
