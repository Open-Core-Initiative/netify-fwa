AUTOMAKE_OPTIONS = foreign

SUBDIRS=debian systemd

TEMPLATEFILES = netify-fwa.sh netify-fwa.ini
TEMPLATEFILES_IN = netify-fwa.sh.in netify-fwa.ini.in

sharedatadir = $(datadir)/$(PACKAGE_TARNAME)

BUILT_SOURCES = $(TEMPLATEFILES)
CLEANFILES = $(TEMPLATEFILES)

EXTRA_DIST = $(TEMPLATEFILES_IN) \
	clearos/10-netify-fwa \
	clearos/netify-fwa.ini \
	netify-fwa.json \
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
	$(INSTALL) -d -m 0755 $(DESTDIR)$(sbindir)
	$(INSTALL) -m 0755 $(PACKAGE).sh $(DESTDIR)$(sbindir)/$(PACKAGE)

install-data-hook:
	$(INSTALL) -d -m 0750 $(DESTDIR)$(persistentstatedir)
	$(INSTALL) -m 0640 $(PACKAGE).ini $(DESTDIR)$(persistentstatedir)
	$(INSTALL) -m 0640 $(PACKAGE).json $(DESTDIR)$(persistentstatedir)
