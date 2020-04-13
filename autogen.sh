#!/bin/sh -x

mkdir -vp m4

# Regenerate configuration files
autoreconf -i --force || exit 1

