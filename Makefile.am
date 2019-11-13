AUTOMAKE_OPTIONS = foreign

SUBDIRS=deploy

TEMPLATEFILES = nfa_defaults.py nfa_version.py
TEMPLATEFILES_IN = nfa_defaults.py.in nfa_version.py.in

sharedatadir = $(datadir)/$(PACKAGE_TARNAME)

install-data-hook:
	$(INSTALL) -D -m 0644 *.py $(DESTDIR)$(sharedatadir)/

BUILT_SOURCES = $(TEMPLATEFILES)
CLEANFILES = $(TEMPLATEFILES)

EXTRA_DIST = \
	autogen.sh \
	inotify_simple.py \
	inotify_test.py \
	nfa_config.py \
	nfa_daemonize.py \
	nfa_fw_clearos.py \
	nfa_fw_firewalld.py \
	nfa_fw_iptables.py \
	nfa_fw_pf.py \
	nfa_fw_pfsense.py \
	nfa_ipset.py \
	nfa_main.py \
	nfa_netify_api.py \
	nfa_netifyd.py \
	nfa_rule.py \
	nfa_task.py \
	$(TEMPLATEFILES_IN)

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
