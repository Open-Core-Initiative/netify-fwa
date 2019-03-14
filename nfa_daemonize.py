# NFA Daemonize
#
# Used docs by Levent Karakas 
# http://www.enderunix.org/documents/eng/daemon.php
# as a reference for this section.
#
# Copyright 2019 Darryl Sokoloski <darryl@egloo.ca>
# Copyright 2007 Jerry Seutter yello (*a*t*) thegeeks.net

import fcntl
import os
import sys
import time
import logging
import logging.handlers

class stream_logger(object):
	def __init__(self, logger, log_level=logging.INFO):
		self.logger = logger
		self.log_level = log_level
		self.linebuf = ''

	def write(self, buf):
		for line in buf.rstrip().splitlines():
			self.logger.log(self.log_level, line.rstrip())

def start(main_func, pid_file=None, debug=False):
    if pid_file is not None:
        fd_lock = open(pid_file, 'w')
        fcntl.lockf(fd_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    # Fork, creating a new process for the child.
    pid = os.fork()
    if pid < 0:
        # Fork error.  Exit badly.
        sys.exit(1)
    elif pid != 0:
        # This is the parent process.  Exit.
        sys.exit(0)

    # This is the child process.  Continue.

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

#    syslog_handler = logging.handlers.SysLogHandler()
#
#    stdout_logger = logging.getLogger('STDOUT')
#    sl = stream_logger(stdout_logger, logging.INFO)
#    sys.stdout = sl
#    stdout_logger.addHandler(syslog_handler)
#
#    stderr_logger = logging.getLogger('STDERR')
#    sl = stream_logger(stderr_logger, logging.ERROR)
#    sys.stderr = sl
#    stderr_logger.addHandler(syslog_handler)

    os.umask(0o027)

    os.chdir('/')

    fd_lock.write('%d' %(os.getpid()))
    fd_lock.flush()

    main_func()
