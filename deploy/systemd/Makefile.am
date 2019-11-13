AUTOMAKE_OPTIONS = foreign

TEMPLATEFILES = netify-fwa.service netify-fwa.conf
TEMPLATEFILES_IN = netify-fwa.service.in netify-fwa.conf.in

sharedatadir = $(datadir)/$(PACKAGE_TARNAME)

if HAVE_SYSTEMD
systemdsystemunit_DATA = @PACKAGE_TARNAME@.service
tmpfiles_DATA = @PACKAGE_TARNAME@.conf
endif

BUILT_SOURCES = $(TEMPLATEFILES)
CLEANFILES = $(TEMPLATEFILES)

EXTRA_DIST = $(TEMPLATEFILES_IN)

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
