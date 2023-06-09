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

#include <Python.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>

#include <netinet/in.h>
#include <net/if.h>
#include <net/pfvar.h>

#include <arpa/inet.h>

#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <netdb.h>

#include "pf.h"

static int pfDevice = -1;
static const char *pfDevicePath = NULL;

static PyMethodDef pfMethods[] = {
    { "open", nfa_pf_open, METH_VARARGS,
        "Open PF device and initialize module state." },

    { "close", nfa_pf_close, METH_VARARGS,
        "Close PF device and clear module state." },

    { "set_syslog", nfa_pf_set_syslog, METH_VARARGS,
        "Set syslog call-back function." },

    { "status", nfa_pf_status, METH_VARARGS,
        "Return the current Packet Filter status." },

    { "anchor_list", nfa_pf_anchor_list, METH_VARARGS,
        "Return a list of anchors." },

    { "anchor_flush", nfa_pf_anchor_flush, METH_VARARGS,
        "Flush rules from anchor." },

    { "table_add", nfa_pf_table_add, METH_VARARGS,
        "Add entry to a table." },

    { "table_delete", nfa_pf_table_delete, METH_VARARGS,
        "Delete entry to a table." },

    { "table_flush", nfa_pf_table_flush, METH_VARARGS,
        "Flush entries from a table." },

    { "table_expire", nfa_pf_table_expire, METH_VARARGS,
        "Expire entries from a table." },

    { "table_kill", nfa_pf_table_kill, METH_VARARGS,
        "Delete a table." },

    { "state_kill_by_host", nfa_pf_state_kill_by_host, METH_VARARGS,
        "Delete states by host." },

    { "state_kill_by_label", nfa_pf_state_kill_by_label, METH_VARARGS,
        "Delete states by label." },

    { NULL, NULL, 0, NULL }
};

static struct PyModuleDef pfModule = {
    PyModuleDef_HEAD_INIT,
    "pf",
    NULL, // Doc
    -1,
    pfMethods
};

PyMODINIT_FUNC PyInit_pf(void)
{
    return PyModule_Create(&pfModule);
}

static PyObject *pfCallbackSyslog = NULL;

static PyObject *nfa_pf_set_syslog(PyObject *self, PyObject *args)
{
    PyObject *temp;
    PyObject *result = NULL;

    if (PyArg_ParseTuple(args, "O:set_syslog", &temp)) {
        if (! PyCallable_Check(temp)) {
            PyErr_SetString(PyExc_TypeError, "parameter must be callable");
            return NULL;
        }

        Py_XINCREF(temp);
        Py_XDECREF(pfCallbackSyslog);
        pfCallbackSyslog = temp;

        Py_INCREF(Py_None);
        result = Py_None;
    }

    return result;
}

static const char *nfa_pf_strerror(void)
{
    switch (errno) {
    case ESRCH:
        return "Table doesn't exist";
    case ENOENT:
    case EINVAL:
        return "Anchor doesn't exist";
    }

    return strerror(errno);
}

static void nfa_pf_printf(int level, const char *format, ...)
{
    if (pfCallbackSyslog == NULL) return;

    va_list ap;
    va_start(ap, format);

    char buffer[PF_MAX_SYSLOG_BUF];

    vsnprintf(buffer, PF_MAX_SYSLOG_BUF, format, ap);

    va_end(ap);

    PyObject *arglist = Py_BuildValue("(is)", level, buffer);
    PyEval_CallObject(pfCallbackSyslog, arglist);

    Py_DECREF(arglist);
}

static PyObject *nfa_pf_open(PyObject *self, PyObject *args)
{
    if (pfDevice != -1) {
        nfa_pf_printf(LOG_WARNING, "nfa_pf_open: %s: device already open.",
            pfDevicePath);
        Py_RETURN_FALSE;
    }

    if (! PyArg_ParseTuple(args, "s:open", &pfDevicePath))
        return NULL;

    int fd = open(pfDevicePath, O_RDWR);

    if (fd < 0) {
        PyErr_SetFromErrno(PyExc_IOError);
        return NULL;
    }

    pfDevice = fd;
    nfa_pf_printf(LOG_DEBUG,
        "%s: opened device: %s: %d", __func__, pfDevicePath, fd);

    Py_RETURN_TRUE;
}

static PyObject *nfa_pf_close(PyObject *self, PyObject *args)
{
    if (pfDevice == -1) {
        nfa_pf_printf(LOG_WARNING, "nfa_pf_close: device is not open");
        Py_RETURN_FALSE;
    }

    if (close(pfDevice) == 0) {
        nfa_pf_printf(LOG_DEBUG,
            "%s: closed device: %s: %d", __func__, pfDevicePath, pfDevice);
    }
    else {
        PyErr_SetFromErrno(PyExc_IOError);
        return NULL;
    }

    pfDevice = -1;
    if (pfDevicePath != NULL) pfDevicePath = NULL;

    Py_RETURN_TRUE;
}

static PyObject *nfa_pf_status(PyObject *self, PyObject *args)
{
    struct pf_status status;

    if (ioctl(pfDevice, DIOCGETSTATUS, &status) < 0) {
        PyErr_SetFromErrno(PyExc_IOError);
        return NULL;
    }

    return PyLong_FromLong(status.running);
}

static PyObject *nfa_pf_anchor_list(PyObject *self, PyObject *args)
{
    const char *anchor;
    struct pfioc_ruleset pr;
    u_int32_t mnr, nr;

    if (! PyArg_ParseTuple(args, "s:anchor_list", &anchor))
        return NULL;

    memset(&pr, 0, sizeof(pr));
    memcpy(pr.path, anchor, sizeof(pr.path));

    if (ioctl(pfDevice, DIOCGETRULESETS, &pr)) {
        PyErr_SetFromErrno(PyExc_IOError);
        return NULL;
    }

    PyObject *po_list = PyList_New(0);

    mnr = pr.nr;
    for (nr = 0; nr < mnr; ++nr) {
        char path[MAXPATHLEN];

        pr.nr = nr;
        if (ioctl(pfDevice, DIOCGETRULESET, &pr)) {
            PyErr_SetFromErrno(PyExc_IOError);
            return NULL;
        }

        if (!strcmp(pr.name, PF_RESERVED_ANCHOR))
            continue;

        path[0] = 0;
        if (pr.path[0]) {
            strlcat(path, pr.path, sizeof(path));
            strlcat(path, "/", sizeof(path));
        }

        strlcat(path, pr.name, sizeof(path));

        PyObject *po_path = PyUnicode_FromString(path);
        PyList_Append(po_list, po_path);
    }

    return po_list;
}

static size_t buf_esize[PFRB_MAX] = { 0,
    sizeof(struct pfr_table), sizeof(struct pfr_tstats),
    sizeof(struct pfr_addr), sizeof(struct pfr_astats),
    sizeof(struct pfi_kif), sizeof(struct pfioc_trans_e)
};

static int pfr_buf_grow(struct pfr_buffer *b, int minsize)
{
    caddr_t p;
    size_t bs;

    if (b == NULL || b->pfrb_type <= 0 || b->pfrb_type >= PFRB_MAX) {
        errno = EINVAL;
        return (-1);
    }

    if (minsize != 0 && minsize <= b->pfrb_msize)
        return (0);

    bs = buf_esize[b->pfrb_type];
    if (!b->pfrb_msize) {
        if (minsize < 64)
            minsize = 64;
    }

    if (minsize == 0)
        minsize = b->pfrb_msize * 2;

    p = reallocarray(b->pfrb_caddr, minsize, bs);
    if (p == NULL)
        return (-1);

    bzero(p + b->pfrb_msize * bs, (minsize - b->pfrb_msize) * bs);
    b->pfrb_caddr = p;
    b->pfrb_msize = minsize;

    return (0);
}

static int pfr_buf_add(struct pfr_buffer *b, const void *e)
{
    size_t bs;

    if (b == NULL || b->pfrb_type <= 0 || b->pfrb_type >= PFRB_MAX ||
        e == NULL) {
        errno = EINVAL;
        return (-1);
    }

    bs = buf_esize[b->pfrb_type];
    if (b->pfrb_size == b->pfrb_msize)
        if (pfr_buf_grow(b, 0))
            return (-1);

    memcpy(((caddr_t)b->pfrb_caddr) + bs * b->pfrb_size, e, bs);
    b->pfrb_size++;

    return (0);
}

static int pfctl_add_trans(struct pfr_buffer *buf, int type, const char *anchor)
{
    struct pfioc_trans_e trans;

    bzero(&trans, sizeof(trans));
    trans.rs_num = type;
    if (strlcpy(trans.anchor, anchor,
        sizeof(trans.anchor)) >= sizeof(trans.anchor)) {
        PyErr_SetString(PyExc_ValueError, "pfctl_add_trans: strlcpy");
        return -1;
    }

    return pfr_buf_add(buf, &trans);
}

static int pfctl_trans(struct pfr_buffer *buf, u_long cmd, int from)
{
    struct pfioc_trans trans;

    bzero(&trans, sizeof(trans));
    trans.size = buf->pfrb_size - from;
    trans.esize = sizeof(struct pfioc_trans_e);
    trans.array = ((struct pfioc_trans_e *)buf->pfrb_caddr) + from;

    return ioctl(pfDevice, cmd, &trans);
}

static PyObject *nfa_pf_anchor_flush(PyObject *self, PyObject *args)
{
    const char *anchor;

    if (! PyArg_ParseTuple(args, "s:anchor_flush", &anchor))
        Py_RETURN_FALSE;

    struct pfr_buffer t;
    memset(&t, 0, sizeof(t));
    t.pfrb_type = PFRB_TRANS;

    if (pfctl_add_trans(&t, PF_RULESET_SCRUB, anchor) ||
        pfctl_add_trans(&t, PF_RULESET_FILTER, anchor) ||
        pfctl_trans(&t, DIOCXBEGIN, 0) ||
        pfctl_trans(&t, DIOCXCOMMIT, 0)) {

        PyErr_SetString(PyExc_ValueError, "flush failed");
        Py_RETURN_FALSE;
    }

    Py_RETURN_TRUE;
}

static int pfr_get_astats(struct pfr_table *tbl, struct pfr_astats *addr, int *size, int flags)
{
    struct pfioc_table io;

    if (tbl == NULL || size == NULL || *size < 0 ||
        (*size && addr == NULL)) {
        errno = EINVAL;
        return (-1);
    }

    bzero(&io, sizeof io);
    io.pfrio_flags = flags;
    io.pfrio_table = *tbl;
    io.pfrio_buffer = addr;
    io.pfrio_esize = sizeof(*addr);
    io.pfrio_size = *size;

    if (ioctl(pfDevice, DIOCRGETASTATS, &io) == -1)
        return (-1);

    *size = io.pfrio_size;

    return (0);
}

static void *pfr_buf_next(struct pfr_buffer *b, const void *prev)
{
    size_t bs;

    if (b == NULL || b->pfrb_type <= 0 || b->pfrb_type >= PFRB_MAX)
        return (NULL);
    if (b->pfrb_size == 0)
        return (NULL);
    if (prev == NULL)
        return (b->pfrb_caddr);
    bs = buf_esize[b->pfrb_type];
    if ((((caddr_t)prev)-((caddr_t)b->pfrb_caddr)) / bs >= b->pfrb_size-1)
        return (NULL);
    return (((caddr_t)prev) + bs);
}

static int pfr_del_addrs(struct pfr_table *tbl, struct pfr_addr *addr, int size, int *ndel, int flags)
{
    struct pfioc_table io;

    if (tbl == NULL || size < 0 || (size && addr == NULL)) {
        errno = EINVAL;
        PyErr_SetFromErrno(PyExc_ValueError);
        return (-1);
    }

    bzero(&io, sizeof io);
    io.pfrio_flags = flags;
    io.pfrio_table = *tbl;
    io.pfrio_buffer = addr;
    io.pfrio_esize = sizeof(*addr);
    io.pfrio_size = size;

    if (ioctl(pfDevice, DIOCRDELADDRS, &io) == -1)
        return (-1);

    if (ndel != NULL)
        *ndel = io.pfrio_ndel;

    return (0);
}

#ifdef _PF_DEBUG
static void print_addrx(const char *prefix, struct pfr_addr *ad, struct pfr_addr *rad)
{
    char b1[1024], b2[1024];
    char ch, buf[256] = "{error}";
    char fb[] = { ' ', 'M', 'A', 'D', 'C', 'Z', 'X', ' ', 'Y', ' ' };
    unsigned int fback, hostnet;

    fback = (rad != NULL) ? rad->pfra_fback : ad->pfra_fback;
    ch = (fback < sizeof(fb) / sizeof(*fb)) ? fb[fback] : '?';
    hostnet = (ad->pfra_af == AF_INET6) ? 128 : 32;
    inet_ntop(ad->pfra_af, &ad->pfra_u, buf, sizeof(buf));

    sprintf(b1, "%c %c%s", ch, (ad->pfra_not ? '!' : ' '), buf);
    b2[0] = 0;
    strcat(b2, b1);

    if (ad->pfra_net < hostnet) {
        sprintf(b1, "/%d", ad->pfra_net);
        strcat(b2, b1);
    }

    if (rad != NULL && fback != PFR_FB_NONE) {
        strlcpy(buf, "{error}", sizeof(buf));
        inet_ntop(rad->pfra_af, &rad->pfra_u, buf, sizeof(buf));
        sprintf(b1, " %c%s", (rad->pfra_not ? '!' : ' '), buf);
        strcat(b2, b1);

        if (rad->pfra_net < hostnet) {
            sprintf(b1, "/%d", rad->pfra_net);
            strcat(b2, b1);
        }
    }

    if (rad != NULL && fback == PFR_FB_NONE) {
        sprintf(b1, " nomatch");
        strcat(b2, b1);
    }

    nfa_pf_printf(LOG_DEBUG, "%s: %s", prefix, b2);
}
#endif // _PF_DEBUG

static PyObject *nfa_pf_table_expire(PyObject *self, PyObject *args)
{
    const char *anchor;
    const char *table;
    u_int ttl;

    //PyRun_SimpleString("print('table_expire')");

    if (! PyArg_ParseTuple(args, "ssI:table_expire", &anchor, &table, &ttl))
        return NULL;

    struct pfr_table t;
    bzero(&t, sizeof(t));

    struct pfr_buffer b1, b2;
    bzero(&b1, sizeof(b1));
    bzero(&b2, sizeof(b2));

    if (strlcpy(t.pfrt_anchor, anchor,
            sizeof(t.pfrt_anchor)) >= sizeof(t.pfrt_anchor) ||
        strlcpy(t.pfrt_name, table,
            sizeof(t.pfrt_name)) >= sizeof(t.pfrt_name)) {
        PyErr_SetString(PyExc_ValueError, "table_expire: strlcpy");
        return NULL;
    }

    b1.pfrb_type = PFRB_ASTATS;
    b2.pfrb_type = PFRB_ADDRS;

    int flags = 0;

    for (;;) {
        pfr_buf_grow(&b1, b1.pfrb_size);
        b1.pfrb_size = b1.pfrb_msize;
        pfr_get_astats(&t, b1.pfrb_caddr, &b1.pfrb_size, flags);
        if (b1.pfrb_size <= b1.pfrb_msize)
            break;
    }

    int expire = 0;
    struct pfr_astats *as;

    PFRB_FOREACH(as, &b1) {
        as->pfras_a.pfra_fback = PFR_FB_NONE;
        if (as->pfras_tzero != 0 && time(NULL) - as->pfras_tzero > ttl) {
#ifdef _PF_DEBUG
            nfa_pf_printf(LOG_DEBUG, "%s, %s: (%d - %d) %d > ttl: %d?",
                    anchor, table,
                    time(NULL), as->pfras_tzero,
                    time(NULL) - as->pfras_tzero, ttl);
#endif
            if (pfr_buf_add(&b2, &as->pfras_a)) {
                PyErr_SetString(PyExc_ValueError, "table_expire: duplicate error");
                return NULL;
            }
            expire++;
        }
    }

    if (b2.pfrb_size > 0) {
#ifdef _PF_DEBUG
        struct pfr_addr *a;
        PFRB_FOREACH(a, &b2) {
            print_addrx("expiring", a, NULL);
        }
#endif
        int expired = 0;
        int rc = pfr_del_addrs(&t, b2.pfrb_caddr, b2.pfrb_size, &expired, flags);
#ifdef _PF_DEBUG
        nfa_pf_printf(LOG_DEBUG,
            "%s: result: %d, expiring: %d (b2 size: %d), expired: %d: %s",
                __func__, rc, expire, b2.pfrb_size, expired, nfa_pf_strerror());
#else
        if (rc != -1 && expired) {
            nfa_pf_printf(LOG_DEBUG,
                "%s: %s, %s: %d", __func__, anchor, table, expired);
        }
#endif
        if (rc) Py_RETURN_FALSE;
    }

    Py_RETURN_TRUE;
}

static int pfr_del_tables(struct pfr_table *tbl, int size, int *ndel, int flags)
{
    struct pfioc_table io;

    if (size < 0 || (size && tbl == NULL)) {
        errno = EINVAL;
        PyErr_SetFromErrno(PyExc_ValueError);
        return (-1);
    }

    bzero(&io, sizeof io);
    io.pfrio_flags = flags;
    io.pfrio_buffer = tbl;
    io.pfrio_esize = sizeof(*tbl);
    io.pfrio_size = size;

    if (ioctl(pfDevice, DIOCRDELTABLES, &io) == -1)
        return (-1);
    if (ndel != NULL)
        *ndel = io.pfrio_ndel;

    return (0);
}

static PyObject *nfa_pf_table_kill(PyObject *self, PyObject *args)
{
    const char *anchor;
    const char *table;

    if (! PyArg_ParseTuple(args, "ss:table_kill", &anchor, &table))
        return NULL;

    struct pfr_table t;
    bzero(&t, sizeof(t));

    if (strlcpy(t.pfrt_anchor, anchor,
            sizeof(t.pfrt_anchor)) >= sizeof(t.pfrt_anchor) ||
        strlcpy(t.pfrt_name, table,
            sizeof(t.pfrt_name)) >= sizeof(t.pfrt_name)) {
        PyErr_SetString(PyExc_ValueError, "table_expire: strlcpy");
        return NULL;
    }

    int killed = 0;
    int rc = pfr_del_tables(&t, 1, &killed, 0);

    if (rc == 0) {
        if (killed) {
            nfa_pf_printf(LOG_DEBUG, "%s: %s, %s", __func__, anchor, table);
            Py_RETURN_TRUE;
        }
    }
    else {
        nfa_pf_printf(LOG_DEBUG, "%s: %s, %s: %s",
            __func__, anchor, table, nfa_pf_strerror());
    }

    Py_RETURN_FALSE;
}

static void nfa_pf_copy_satopfaddr(struct pf_addr *pfa, struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET6)
        pfa->v6 = ((struct sockaddr_in6 *)sa)->sin6_addr;
    else if (sa->sa_family == AF_INET)
        pfa->v4 = ((struct sockaddr_in *)sa)->sin_addr;
}

static void nfa_pf_set_ipmask(struct node_host *h, int bb)
{
    struct pf_addr *m, *n;
    int i, j = 0;
    u_int8_t b;

    m = &h->addr.v.a.mask;
    memset(m, 0, sizeof(*m));

    if (bb == -1)
        b = h->af == AF_INET ? 32 : 128;
    else
        b = bb;

    while (b >= 32) {
        m->addr32[j++] = 0xffffffff;
        b -= 32;
    }

    for (i = 31; i > 31-b; --i)
        m->addr32[j] |= (1 << i);

    if (b)
        m->addr32[j] = htonl(m->addr32[j]);

    n = &h->addr.v.a.addr;
    if (h->addr.type == PF_ADDR_ADDRMASK) {
        for (i = 0; i < 4; i++)
            n->addr32[i] = n->addr32[i] & m->addr32[i];
    }
}

static struct node_host *nfa_pf_host_ip(const char *s, int mask)
{
    struct addrinfo hints, *res;
    struct node_host *h = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICHOST;

    if (getaddrinfo(s, NULL, &hints, &res) == 0) {
        h = calloc(1, sizeof(*h));
        if (h == NULL) {
            nfa_pf_printf(LOG_DEBUG, "%s: calloc, %s",
                __func__, nfa_pf_strerror());
            return NULL;
        }

        h->af = res->ai_family;
        nfa_pf_copy_satopfaddr(&h->addr.v.a.addr, res->ai_addr);

        if (h->af == AF_INET6)
            h->ifindex =
                ((struct sockaddr_in6 *)res->ai_addr)->sin6_scope_id;

        freeaddrinfo(res);

    } else {
        if (mask == -1)
            return (NULL);

        h = calloc(1, sizeof(*h));
        if (h == NULL) {
            nfa_pf_printf(LOG_DEBUG, "%s: calloc, %s",
                __func__, nfa_pf_strerror());
            return NULL;
        }

        h->af = AF_INET;
        if (inet_net_pton(AF_INET, s, &h->addr.v.a.addr.v4,
            sizeof(h->addr.v.a.addr.v4)) == -1) {
            free(h);
            return (NULL);
        }
    }

    nfa_pf_set_ipmask(h, mask);

    h->ifname = NULL;
    h->next = NULL;
    h->tail = h;

    return (h);
}

static struct node_host *nfa_pf_host(const char *s)
{
    int mask = -1;
    struct node_host *h = NULL, *n;
    char *p, *ps, *if_name;
    const char *errstr;

    if ((ps = strdup(s)) == NULL) {
        nfa_pf_printf(LOG_DEBUG, "%s: strdup, %s",
            __func__, nfa_pf_strerror());
        return NULL;
    }

    if ((if_name = strrchr(ps, '@')) != NULL) {
        if_name[0] = '\0';
        if_name++;
    }

    if ((p = strchr(ps, '/')) != NULL) {
        mask = strtonum(p + 1, 0, 128, &errstr);
        if (errstr) {
            nfa_pf_printf(LOG_DEBUG, "%s: netmask, %s: %s",
                __func__, errstr, p);
            goto error;
        }

        p[0] = '\0';
    }

    if ((h = nfa_pf_host_ip(ps, mask)) == NULL) {
        nfa_pf_printf(LOG_DEBUG, "%s: IP address not found: %s",
            __func__, s);
        goto error;
    }

    if (if_name && if_name[0]) {
        for (n = h; n != NULL; n = n->next) {
            if ((n->ifname = strdup(if_name)) == NULL) {
                nfa_pf_printf(LOG_DEBUG, "%s: strdup, %s",
                    __func__, nfa_pf_strerror());
                h = NULL;
                goto error;
            }
        }
    }

    for (n = h; n != NULL; n = n->next) {
        n->addr.type = PF_ADDR_ADDRMASK;
        n->weight = 0;
    }

error:
    free(ps);
    return (h);
}

static int nfa_pf_unmask(struct pf_addr *m)
{
    int i = 31, j = 0, b = 0;
    u_int32_t tmp;

    while (j < 4 && m->addr32[j] == 0xffffffff) {
        b += 32;
        j++;
    }

    if (j < 4) {
        tmp = ntohl(m->addr32[j]);
        for (i = 31; tmp & (1 << i); --i)
            b++;
    }

    return (b);
}

static int nfa_pf_append_host(struct pfr_buffer *b, struct node_host *n)
{
    int bits;
    struct pfr_addr addr;

    do {
        bzero(&addr, sizeof(addr));
        addr.pfra_af = n->af;
        addr.pfra_net = nfa_pf_unmask(&n->addr.v.a.mask);

        switch (n->af) {
        case AF_INET:
            addr.pfra_ip4addr.s_addr = n->addr.v.a.addr.addr32[0];
            bits = 32;
            break;
        case AF_INET6:
            memcpy(&addr.pfra_ip6addr, &n->addr.v.a.addr.v6,
                sizeof(struct in6_addr));
            bits = 128;
            break;
        default:
            errno = EINVAL;
            nfa_pf_printf(LOG_DEBUG, "%s: address family: %s",
                __func__, nfa_pf_strerror());
            return (-1);
        }

        if (addr.pfra_net != bits || addr.pfra_net > bits) {
            nfa_pf_printf(LOG_DEBUG, "%s: network bits: %s",
                __func__, nfa_pf_strerror());
            errno = EINVAL;
            return (-1);
        }

        if (pfr_buf_add(b, &addr))
            return (-1);

    } while ((n = n->next) != NULL);

    return (0);
}

static int pfr_add_tables(struct pfr_table *tbl, int size, int *nadd, int flags)
{
    struct pfioc_table io;

    if (size < 0 || (size && tbl == NULL)) {
        errno = EINVAL;
        return (-1);
    }

    bzero(&io, sizeof io);
    io.pfrio_flags = flags;
    io.pfrio_buffer = tbl;
    io.pfrio_esize = sizeof(*tbl);
    io.pfrio_size = size;

    if (ioctl(pfDevice, DIOCRADDTABLES, &io) == -1)
        return (-1);

    if (nadd != NULL)
        *nadd = io.pfrio_nadd;

    return (0);
}

static int pfr_add_addrs(struct pfr_table *tbl, struct pfr_addr *addr, int size, int *nadd, int flags)
{
    struct pfioc_table io;

    if (tbl == NULL || size < 0 || (size && addr == NULL)) {
        errno = EINVAL;
        return (-1);
    }

    bzero(&io, sizeof io);
    io.pfrio_flags = flags;
    io.pfrio_table = *tbl;
    io.pfrio_buffer = addr;
    io.pfrio_esize = sizeof(*addr);
    io.pfrio_size = size;

    if (ioctl(pfDevice, DIOCRADDADDRS, &io) == -1)
        return (-1);

    if (nadd != NULL)
        *nadd = io.pfrio_nadd;

    return (0);
}

static PyObject *nfa_pf_table_add(PyObject *self, PyObject *args)
{
    const char *anchor;
    const char *table;
    const char *host;

    if (! PyArg_ParseTuple(args, "sss:table_add", &anchor, &table, &host))
        return NULL;

    struct pfr_buffer b1;
    bzero(&b1, sizeof(b1));

    b1.pfrb_type = PFRB_ADDRS;

    struct pfr_table t;
    bzero(&t, sizeof(t));

    if (strlcpy(t.pfrt_anchor, anchor,
            sizeof(t.pfrt_anchor)) >= sizeof(t.pfrt_anchor) ||
        strlcpy(t.pfrt_name, table,
            sizeof(t.pfrt_name)) >= sizeof(t.pfrt_name)) {
        PyErr_SetString(PyExc_ValueError, "table_add: strlcpy");
        return NULL;
    }

    t.pfrt_flags |= PFR_TFLAG_PERSIST;

    int flags = 0, table_added = 0;
    pfr_add_tables(&t, 1, &table_added, flags);

    t.pfrt_flags &= ~PFR_TFLAG_PERSIST;

    struct node_host *nh;
    if ((nh = nfa_pf_host(host)) == NULL)
        return NULL;

    if (nfa_pf_append_host(&b1, nh) == -1)
        return NULL;

    int added = 0;
    int rc = pfr_add_addrs(&t, b1.pfrb_caddr, b1.pfrb_size, &added, flags);

    if (rc == 0) {
        if (added) {
            nfa_pf_printf(LOG_DEBUG, "%s: %s, %s: %s",
                __func__, anchor, table, host);
            Py_RETURN_TRUE;
        }
    }
    else {
        int level = LOG_DEBUG;
        if (errno != ESRCH && errno != EINVAL && errno != ENOENT)
            level = LOG_ERR;

        nfa_pf_printf(LOG_ERR, "%s: %s, %s: %s: %s",
            __func__, anchor, table, host, nfa_pf_strerror());
    }

    Py_RETURN_FALSE;
}

static PyObject *nfa_pf_table_delete(PyObject *self, PyObject *args)
{
    const char *anchor;
    const char *table;
    const char *host;

    if (! PyArg_ParseTuple(args, "sss:table_delete", &anchor, &table, &host))
        return NULL;

    struct pfr_buffer b1;
    bzero(&b1, sizeof(b1));

    b1.pfrb_type = PFRB_ADDRS;

    struct pfr_table t;
    bzero(&t, sizeof(t));

    if (strlcpy(t.pfrt_anchor, anchor,
            sizeof(t.pfrt_anchor)) >= sizeof(t.pfrt_anchor) ||
        strlcpy(t.pfrt_name, table,
            sizeof(t.pfrt_name)) >= sizeof(t.pfrt_name)) {
        PyErr_SetString(PyExc_ValueError, "table_delete: strlcpy");
        return NULL;
    }

    struct node_host *nh;
    if ((nh = nfa_pf_host(host)) == NULL)
        return NULL;

    if (nfa_pf_append_host(&b1, nh) == -1)
        return NULL;

    int deleted = 0, flags = 0;
    int rc = pfr_del_addrs(&t, b1.pfrb_caddr, b1.pfrb_size, &deleted, flags);

    if (rc == 0) {
        if (deleted) {
            nfa_pf_printf(LOG_DEBUG, "%s: %s, %s: %s",
                __func__, anchor, table, host);
            Py_RETURN_TRUE;
        }
    }
    else {
        int level = LOG_DEBUG;
        if (errno != ESRCH && errno != EINVAL && errno != ENOENT)
            level = LOG_ERR;

        nfa_pf_printf(LOG_ERR, "%s: %s, %s: %s: %s",
            __func__, anchor, table, host, nfa_pf_strerror());
    }

    Py_RETURN_FALSE;
    return NULL;
}

static int pfr_clr_addrs(struct pfr_table *tbl, int *ndel, int flags)
{
    struct pfioc_table io;

    if (tbl == NULL) {
        errno = EINVAL;
        return (-1);
    }

    bzero(&io, sizeof io);
    io.pfrio_flags = flags;
    io.pfrio_table = *tbl;

    if (ioctl(pfDevice, DIOCRCLRADDRS, &io) == -1)
        return (-1);

    if (ndel != NULL)
        *ndel = io.pfrio_ndel;

    return (0);
}

static PyObject *nfa_pf_table_flush(PyObject *self, PyObject *args)
{
    const char *anchor;
    const char *table;

    if (! PyArg_ParseTuple(args, "ss:table_flush", &anchor, &table))
        return NULL;

    struct pfr_table t;
    bzero(&t, sizeof(t));

    if (strlcpy(t.pfrt_anchor, anchor,
            sizeof(t.pfrt_anchor)) >= sizeof(t.pfrt_anchor) ||
        strlcpy(t.pfrt_name, table,
            sizeof(t.pfrt_name)) >= sizeof(t.pfrt_name)) {
        PyErr_SetString(PyExc_ValueError, "table_expire: strlcpy");
        return NULL;
    }

    int flushed = 0;
    int rc = pfr_clr_addrs(&t, &flushed, 0);

    if (rc == 0) {
        if (flushed) {
            nfa_pf_printf(LOG_DEBUG, "%s: %s, %s: %d",
                __func__, anchor, table, flushed);
            Py_RETURN_TRUE;
        }
    }
    else {
        int level = LOG_DEBUG;
        if (errno != ESRCH && errno != EINVAL && errno != ENOENT)
            level = LOG_ERR;

        nfa_pf_printf(LOG_ERR, "%s: %s, %s: %s",
            __func__, anchor, table, nfa_pf_strerror());
    }

    Py_RETURN_FALSE;
}

static PyObject *nfa_pf_state_kill_by_label(PyObject *self, PyObject *args)
{
    const char *label;

    if (! PyArg_ParseTuple(args, "s:state_kill_by_label", &label))
        return NULL;

    struct pfioc_state_kill psk;
    bzero(&psk, sizeof(psk));

    if (strlcpy(psk.psk_label, label, sizeof(psk.psk_label)) >=
        sizeof(psk.psk_label)) {
        PyErr_SetString(PyExc_ValueError, "state_kill_by_label: strlcpy");
        return NULL;
    }

    if (ioctl(pfDevice, DIOCKILLSTATES, &psk) == -1) {
        PyErr_SetFromErrno(PyExc_IOError);
        return NULL;
    }

    if (psk.psk_killed)
        nfa_pf_printf(LOG_DEBUG, "%s: %s: %d", __func__, label, psk.psk_killed);

    Py_RETURN_TRUE;
}

static struct addrinfo *pfctl_addrprefix(const char *addr, struct pf_addr *mask)
{
    char *p;
    const char *errstr;
    int prefix, ret_ga, q, r;
    struct addrinfo hints, *res;

    bzero(&hints, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICHOST;

    if ((p = strchr(addr, '/')) != NULL)
        *p++ = '\0';

    if ((ret_ga = getaddrinfo(addr, NULL, &hints, &res))) {
        PyErr_SetString(PyExc_ValueError, gai_strerror(ret_ga));
        return NULL;
    }

    if (p == NULL)
        return res;

    prefix = strtonum(p, 0, res->ai_family == AF_INET6 ? 128 : 32, &errstr);
    if (errstr) {
        PyErr_SetString(PyExc_ValueError, errstr);
        return NULL;
    }

    q = prefix >> 3;
    r = prefix & 7;
    switch (res->ai_family) {
    case AF_INET:
        bzero(&mask->v4, sizeof(mask->v4));
        mask->v4.s_addr = htonl((u_int32_t)
            (0xffffffffffULL << (32 - prefix)));
        break;
    case AF_INET6:
        bzero(&mask->v6, sizeof(mask->v6));
        if (q > 0)
            memset((void *)&mask->v6, 0xff, q);
        if (r > 0)
            *((u_char *)&mask->v6 + q) =
                (0xff00 >> r) & 0xff;
        break;
    }

    return res;
}

static PyObject *nfa_pf_state_kill_by_host(PyObject *self, PyObject *args)
{
    const char *host;
    char mask[16];

    if (! PyArg_ParseTuple(args, "s:state_kill_by_host", &host))
        return NULL;

    struct pfioc_state_kill psk;
    bzero(&psk, sizeof(psk));
    memset(&psk.psk_src.addr.v.a.mask, 0xff, sizeof(psk.psk_src.addr.v.a.mask));

    struct sockaddr last_src, last_dst;
    memset(&last_src, 0xff, sizeof(last_src));
    memset(&last_dst, 0xff, sizeof(last_dst));

    int killed, sources, dests;
    killed = sources = dests = 0;

    struct addrinfo *res[2], *resp[2];
    strcpy(mask, "0.0.0.0/0");
    res[0] = pfctl_addrprefix(mask, &psk.psk_src.addr.v.a.mask);

    for (resp[0] = res[0]; resp[0]; resp[0] = resp[0]->ai_next) {

        if (resp[0]->ai_addr == NULL)
            continue;

        if (memcmp(&last_src, resp[0]->ai_addr, sizeof(last_src)) == 0)
            continue;

        last_src = *(struct sockaddr *)resp[0]->ai_addr;

        psk.psk_af = resp[0]->ai_family;
        sources++;

        nfa_pf_copy_satopfaddr(&psk.psk_src.addr.v.a.addr, resp[0]->ai_addr);

        dests = 0;

        memset(&psk.psk_dst.addr.v.a.mask, 0xff, sizeof(psk.psk_dst.addr.v.a.mask));
        memset(&last_dst, 0xff, sizeof(last_dst));

        res[1] = pfctl_addrprefix(host, &psk.psk_dst.addr.v.a.mask);

        for (resp[1] = res[1]; resp[1]; resp[1] = resp[1]->ai_next) {

            if (resp[1]->ai_addr == NULL)
                continue;

            if (psk.psk_af != resp[1]->ai_family)
                continue;

            if (memcmp(&last_dst, resp[1]->ai_addr, sizeof(last_dst)) == 0)
                continue;

            last_dst = *(struct sockaddr *)resp[1]->ai_addr;

            dests++;

            nfa_pf_copy_satopfaddr(&psk.psk_dst.addr.v.a.addr, resp[1]->ai_addr);

            if (ioctl(pfDevice, DIOCKILLSTATES, &psk) == -1) {
                PyErr_SetFromErrno(PyExc_IOError);
                return NULL;
            }

            killed += psk.psk_killed;
        }

        freeaddrinfo(res[1]);
    }

    freeaddrinfo(res[0]);

    if (killed)
        nfa_pf_printf(LOG_DEBUG, "%s: %s: %d", __func__, host, killed);

    Py_RETURN_TRUE;
}
