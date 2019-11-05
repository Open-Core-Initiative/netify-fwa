#!/bin/sh

[ -x /opt/rh/rh-python36/enable ] && . /opt/rh/rh-python36/enable

cd /usr/share/netify-fwa || exit 1

exec ./nfa_main.py $@
