// Netify Firewall Agent - PF Extension
// Copyright (C) 2001 Daniel Hartmeier
// Copyright (C) 2002-2013 Henning Brauer <henning@openbsd.org>
// Copyright (C) 2020 eGloo Incorporated <http://www.egloo.ca>
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//    - Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//    - Redistributions in binary form must reproduce the above
//      copyright notice, this list of conditions and the following
//      disclaimer in the documentation and/or other materials provided
//      with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#ifndef _PF_H
#define _PF_H

#define PF_MAX_SYSLOG_BUF   1024

enum {
    PFRB_TABLES = 1, PFRB_TSTATS, PFRB_ADDRS, PFRB_ASTATS,
    PFRB_IFACES, PFRB_TRANS, PFRB_MAX
};

#define PFRB_FOREACH(var, buf) \
    for ((var) = pfr_buf_next((buf), NULL); \
        (var) != NULL; \
        (var) = pfr_buf_next((buf), (var)))

struct pfr_buffer {
    int pfrb_type;
    int pfrb_size;
    int pfrb_msize;
    void *pfrb_caddr;
};

struct node_host {
    struct pf_addr_wrap addr;
    struct pf_addr bcast;
    struct pf_addr peer;
    sa_family_t af;
    u_int8_t not;
    u_int32_t ifindex;
    u_int16_t weight;
    char *ifname;
    u_int ifa_flags;
    struct node_host *next;
    struct node_host *tail;
};

static PyObject *nfa_pf_open(PyObject *self, PyObject *args);
static PyObject *nfa_pf_close(PyObject *self, PyObject *args);

static PyObject *nfa_pf_set_syslog(PyObject *self, PyObject *args);

static PyObject *nfa_pf_status(PyObject *self, PyObject *args);

static PyObject *nfa_pf_anchor_flush(PyObject *self, PyObject *args);
static PyObject *nfa_pf_anchor_list(PyObject *self, PyObject *args);

static PyObject *nfa_pf_table_add(PyObject *self, PyObject *args);
static PyObject *nfa_pf_table_delete(PyObject *self, PyObject *args);
static PyObject *nfa_pf_table_expire(PyObject *self, PyObject *args);
static PyObject *nfa_pf_table_flush(PyObject *self, PyObject *args);
static PyObject *nfa_pf_table_kill(PyObject *self, PyObject *args);

static PyObject *nfa_pf_state_kill_by_host(PyObject *self, PyObject *args);
static PyObject *nfa_pf_state_kill_by_label(PyObject *self, PyObject *args);

#endif // _PF_H
