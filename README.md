# Netify Firewall Agent

Netify FWA (Firewall Agent) receives near real-time network flow detections from a companion Netify Agent daemon.  These flows are compared against a dynamic ruleset and when matched a corresponding firewall action is taken (for example, block or prioritize).

This Python version supersedes the former PHP example implementation and is designed to support numerous firewall backends.

Currently, the following firewall drivers are included:
- IPTables (vanilla iptables).
- ClearOS (custom iptables).
- Firewalld (custom iptables).
- PF (vanilla pf - not fully tested/implemented).
- pfSense (PF).

## Requirements

- Python 3.6.
- Firewalld driver requires firewalld.
- All IPTables derivatives require ipset.

## Package Downloads

At this time the only available package for download is for pfSense:
- pfSense [2.4.x](http://download.netify.ai/netify/pfsense/2.4.x/)

## Build/install from Source

Clone the source and either build a package or install directly from source:
```sh
git clone https://gitlab.com/netify.ai/public/netify-fwa.git
cd netify-fwa
./autogen.sh
```
### Package
For RPM-based operating systems:
```sh
./configure [options and flags such as --prefix, etc]
make dist-gzip
cp netify-fwa*.tar.gz ~/rpmbuild/SOURCES/
rpmbuild -ba ./deploy/rpm/netify-fwa.spec
```

### Install
To install netify directly on the running system:
```sh
./configure [options and flags such as --prefix, etc]
sudo make install
```

To generate a tar/gz archive that can be unpacked on another target host:
```sh
./configure [options and flags such as --prefix, etc]
make install DESTDIR=/tmp/netify-fwa
cd /tmp/netify-fwa && tar cvzf ../netify-fwa.tar.gz .
```

### Documentation
Some internal documentation about how to configure Netify FWA with a dynamic JSON-based ruleset can be found [here](https://docs.google.com/document/d/1sDI18yLYDCVj4Fm53M1Yl2X7vkNHjjuBxiLx5sUwNv4/edit?usp=sharing).
### License
>>>
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
>>>