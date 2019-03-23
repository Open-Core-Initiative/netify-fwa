# NFA Daemonize
#
# Used docs by Levent Karakas 
# http://www.enderunix.org/documents/eng/daemon.php
# as a reference for this section.
#
# Copyright 2019 Darryl Sokoloski <darryl@egloo.ca>
# Copyright 2007 Jerry Seutter yello (*a*t*) thegeeks.net

import os
import sys
import fcntl

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

def create(pid_file=None, debug=False):
    if pid_file is not None:
        try:
            fd_lock = open(pid_file, 'w+')
            fcntl.flock(fd_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except FileNotFoundError as e:
            syslog(LOG_ERR, "Unable to create PID file: %s" %(pid_file))
            sys.exit(1)

    # Fork, creating a new process for the child.
    pid = os.fork()
    if pid < 0:
        # Fork error.  Exit badly.
        sys.exit(1)
    elif pid != 0:
        # This is the parent process.  Exit.
        sys.exit(0)

    # This is the child process.  Continue.
    if pid_file is not None:
        fd_lock.write('%d' %(os.getpid()))
        fd_lock.flush()

    pid = os.setsid()
    if pid == -1:
        sys.exit(1)

    if not debug:
        path_null = '/dev/null'
        if hasattr(os, 'devnull'):
            path_null = os.devnull

        fd_null = open(path_null, 'w+')
        for fd in (sys.stdin, sys.stdout, sys.stderr):
            fd.close()
            fd = fd_null

    os.umask(0o027)

    os.chdir('/')
