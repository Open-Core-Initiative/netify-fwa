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

#endif // _PF_H
