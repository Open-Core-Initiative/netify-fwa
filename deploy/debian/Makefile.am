# Netify FWA Debian Package Automake File
# Copyright (C) 2021 eGloo, Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

DEBFILES = debian.changelog debian.conffiles debian.control debian.init debian.postinst debian.rules netify-fwa.dsc
DEBFILES_IN = debian.changelog.in debian.conffiles.in debian.control.in debian.init debian.postinst.in debian.rules.in netify-fwa.dsc.in

BUILT_SOURCES = $(DEBFILES)
CLEANFILES = $(DEBFILES)
EXTRA_DIST = $(DEBFILES_IN)

%: %.in
	$(SED) \
		-e 's|[@]bindir@|$(bindir)|g' \
		-e 's|[@]datadir@|$(datadir)/$(PACKAGE_TARNAME)|g' \
		-e 's|[@]includedir@|$(includedir)|g' \
		-e 's|[@]libdir@|$(libdir)|g' \
		-e 's|[@]PACKAGE_BUGREPORT@|$(PACKAGE_BUGREPORT)|g' \
		-e 's|[@]PACKAGE_NAME@|$(PACKAGE_NAME)|g' \
		-e 's|[@]PACKAGE_TARNAME@|$(PACKAGE_TARNAME)|g' \
		-e 's|[@]PACKAGE_VERSION@|$(PACKAGE_VERSION)|g' \
		-e 's|[@]sbindir@|$(sbindir)|g' \
		-e 's|[@]sysconfdir@|$(sysconfdir)|g' \
		-e 's|[@]volatilestatedir@|$(volatilestatedir)|g' \
		< "$<" > "$@"
