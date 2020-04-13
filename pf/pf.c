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

    { "table_expire", nfa_pf_table_expire, METH_VARARGS,
        "Expire entries from a table." },

    { "table_kill", nfa_pf_table_kill, METH_VARARGS,
        "Delete a table." },

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
        "%s: opened device: %s: %d", "open", pfDevicePath, fd);

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
            "%s: closed device: %s: %d", "close", pfDevicePath, pfDevice);
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
    int fd;
    struct pf_status status;

    if (ioctl(pfDevice, DIOCGETSTATUS, &status) < 0) {
        PyErr_SetFromErrno(PyExc_IOError);
        return NULL;
    }

    return PyLong_FromLong(status.running);
}

static PyObject *nfa_pf_anchor_list(PyObject *self, PyObject *args)
{
    int fd;
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
    int fd;
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
/*
    if (ad->pfra_ifname[0] != '\0') {
        sprintf(b1, "@%s", ad->pfra_ifname);
        strcat(b2, b1);
    }
*/
    nfa_pf_printf(LOG_DEBUG, "%s: %s", prefix, b2);
}

static PyObject *nfa_pf_table_expire(PyObject *self, PyObject *args)
{
    int fd;
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
            nfa_pf_printf(LOG_DEBUG, "%s/%s: (%d - %d) %d > ttl: %d?",
                    anchor, table,
                    time(NULL), as->pfras_tzero,
                    time(NULL) - as->pfras_tzero, ttl);
            if (pfr_buf_add(&b2, &as->pfras_a)) {
                PyErr_SetString(PyExc_ValueError, "table_expire: duplicate error");
                return NULL;
            }
            expire++;
        }
    }

    if (b2.pfrb_size > 0) {
        struct pfr_addr *a;
        PFRB_FOREACH(a, &b2) {
            print_addrx("expiring", a, NULL);
        }

        int expired = 0;
        int rc = pfr_del_addrs(&t, b2.pfrb_caddr, b2.pfrb_size, &expired, flags);

        nfa_pf_printf(LOG_DEBUG,
            "%s: result: %d, expiring: %d (b2 size: %d), expired: %d: %s",
                "table_expire", rc, expire, b2.pfrb_size, expired, strerror(errno));

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
    int fd;
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
            nfa_pf_printf(LOG_DEBUG, "%s: %s/%s", "table_kill", anchor, table);
            Py_RETURN_TRUE;
        }
    }
    else {
        nfa_pf_printf(LOG_DEBUG, "%s: %s/%s: %s",
            "table_kill", anchor, table, strerror(errno));
    }

    Py_RETURN_FALSE;
}

