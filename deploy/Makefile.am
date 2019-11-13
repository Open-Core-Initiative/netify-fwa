AUTOMAKE_OPTIONS = foreign

SUBDIRS=systemd

TEMPLATEFILES = netify-fwa.sh
TEMPLATEFILES_IN = netify-fwa.sh.in

sharedatadir = $(datadir)/$(PACKAGE_TARNAME)

BUILT_SOURCES = $(TEMPLATEFILES)
CLEANFILES = $(TEMPLATEFILES)

EXTRA_DIST = $(TEMPLATEFILES_IN) \
	pfsense/files \
	pfsense/Makefile.in \
	pfsense/pkg-descr \
	pfsense/pkg-message \
	pfsense/pkg-plist

%: %.in
	$(SED) \
		-e 's|[@]sbindir@|$(sbindir)|g' \
		-e 's|[@]sharedatadir@|$(sharedatadir)|g' \
		-e 's|[@]PACKAGE_NAME@|$(PACKAGE_NAME)|g' \
		-e 's|[@]PACKAGE_TARNAME@|$(PACKAGE_TARNAME)|g' \
		-e 's|[@]PACKAGE_VERSION@|$(PACKAGE_VERSION)|g' \
		-e 's|[@]sysconfdir@|$(sysconfdir)|g' \
		-e 's|[@]persistentstatedir@|$(persistentstatedir)|g' \
		-e 's|[@]volatilestatedir@|$(volatilestatedir)|g' \
		< "$<" > "$@"

install-exec-hook:
	$(INSTALL) -D -m 0755 $(PACKAGE).sh $(DESTDIR)$(sbindir)/$(PACKAGE)
