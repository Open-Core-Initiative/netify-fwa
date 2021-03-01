AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

SUBDIRS_EXTRA =
if USE_PF
SUBDIRS_EXTRA += pf
endif

SUBDIRS=deploy $(SUBDIRS_EXTRA)

TEMPLATEFILES = nfa_defaults.py nfa_version.py
TEMPLATEFILES_IN = nfa_defaults.py.in nfa_version.py.in

sharedatadir = $(datadir)/$(PACKAGE_TARNAME)

BUILT_SOURCES = $(TEMPLATEFILES)
CLEANFILES = $(TEMPLATEFILES)

EXTRA_DIST = \
	LICENSE \
	autogen.sh \
	debian/compat \
	inotify_simple.py \
	inotify_test.py \
	nfa_config.py \
	nfa_daemonize.py \
	nfa_fw_clearos.py \
	nfa_fw_firewalld.py \
	nfa_fw_iptables.py \
	nfa_fw_openwrt.py \
	nfa_fw_pf.py \
	nfa_fw_pfsense.py \
	nfa_global.py \
	nfa_ipset.py \
	nfa_main.py \
	nfa_netify_api.py \
	nfa_netifyd.py \
	nfa_rule.py \
	nfa_task.py \
	nfa_timer.py \
	nfa_util.py \
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

install-data-hook:
	$(INSTALL) -d -m 0755 $(DESTDIR)$(sharedatadir)
	$(INSTALL) -m 0644 *.py $(DESTDIR)$(sharedatadir)/

deploy-pfsense:
	./autogen.sh && ./configure
	$(MAKE) -C deploy
	$(MAKE) dist-gzip
	sudo cp -v $(PACKAGE)-$(VERSION).tar.gz /usr/ports/distfiles/
	make -C deploy/pfsense clean
	make -C deploy/pfsense makesum
	make -C deploy/pfsense package DISABLE_VULNERABILITIES=yes
	ls -lh deploy/pfsense/work/pkg/*.txz

dist-git:
	rm -f $(PACKAGE)-$(VERSION).tar*
	git archive --prefix=$(PACKAGE)-$(VERSION)/ --output=$(PACKAGE)-$(VERSION).tar HEAD
	p=`pwd`; (echo .; git submodule foreach) | while read entering path; do \
		temp="$${path%\'}"; \
		temp="$${temp#\'}"; \
		path=$$temp; \
		[ "$$path" = "" ] && continue; \
		(cd $$path && \
			git archive --prefix=$(PACKAGE)-$(VERSION)/$$path/ --output=/tmp/$(PACKAGE)-submodule.tar HEAD && \
			$(AMTAR) --concatenate --file="$$p/$(PACKAGE)-$(VERSION).tar" /tmp/$(PACKAGE)-submodule.tar && \
			rm -f /tmp/$(PACKAGE)-submodule.tar \
		); \
	done
	gzip $(PACKAGE)-$(VERSION).tar

if HAVE_OSC
deploy-osc-update: dist-git
	./autogen.sh && \
		./configure --prefix=/usr --includedir=\${prefix}/include \
		--mandir=\${prefix}/share/man --sysconfdir=/etc --localstatedir=/var

	$(MAKE) clean
	$(MAKE) -C deploy/debian

	(cd $(HOME)/netify-osc/home\:egloo/netify-fwa && $(osc) update)
	cp deploy/debian/debian.changelog $(HOME)/netify-osc/home\:egloo/netify-fwa
	cp deploy/debian/debian.conffiles $(HOME)/netify-osc/home\:egloo/netify-fwa
	cp deploy/debian/debian.control $(HOME)/netify-osc/home\:egloo/netify-fwa
	cp deploy/debian/debian.postinst $(HOME)/netify-osc/home\:egloo/netify-fwa
	chmod a+x $(HOME)/netify-osc/home\:egloo/netify-fwa/debian.postinst
	cp deploy/debian/debian.rules $(HOME)/netify-osc/home\:egloo/netify-fwa
	cp deploy/debian/netify-fwa.dsc $(HOME)/netify-osc/home\:egloo/netify-fwa
	cp deploy/rpm/netify-fwa*.spec $(HOME)/netify-osc/home\:egloo/netify-fwa
	(cd $(HOME)/netify-osc/home\:egloo/netify-fwa && $(osc) rm --force $(PACKAGE)-*.tar.gz || true)
	cp $(PACKAGE)-$(VERSION).tar.gz $(HOME)/netify-osc/home\:egloo/netify-fwa
	(cd $(HOME)/netify-osc/home\:egloo/netify-fwa && $(osc) add $(PACKAGE)-*.tar.gz)
	(cd $(HOME)/netify-osc/home\:egloo/netify-fwa && $(osc) status)

deploy-osc-commit: deploy-osc-update
	(cd $(HOME)/netify-osc/home\:egloo/netify-fwa && $(osc) commit -m 'Updated to latest sources.')
endif
