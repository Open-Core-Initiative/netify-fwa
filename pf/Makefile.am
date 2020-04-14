# Netify Agent Source Automake File
# Copyright (C) 2016-2019 eGloo, Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

AUTOMAKE_OPTIONS = foreign

AM_CPPFLAGS = $(CPPFLAGS) -D_GNU_SOURCE -I $(top_srcdir)/pf $(PYTHON36_CFLAGS)

lib_LTLIBRARIES = libpf.la
libpf_la_SOURCES = pf.c
libpf_la_LIBADD = $(PYTHON36_LIBS)

noinst_HEADERS = pf.h
