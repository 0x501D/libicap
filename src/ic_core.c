#include "ic_core.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>

#include "../libicap.h"

#include "ic_err.h"
#include "ic_utils.h"

typedef enum ic_method {
    IC_METHOD_ID_REQ,    /* REQMOD - for Request Modification      */
    IC_METHOD_ID_RESP,   /* RESPMOD - for Response Modification    */
    IC_METHOD_ID_OPTS    /* OPTIONS - to learn about configuration */
} ic_method_t;

typedef struct ic_opts {
    uint32_t preview_len;
    unsigned int allow_204:1;
    unsigned int m_resp:1;
    unsigned int m_req:1;
} ic_opts_t;

typedef struct ic_cl_ctx {
    ic_opts_t opts;
    ic_ctx_type_t type;
    size_t req_hdr_len;
    size_t res_hdr_len;
    size_t body_len;
    size_t payload_len;
    uint64_t body_sended;
    uint64_t content_len;
    uint64_t total_sended;
    int icap_hdr_len;
    unsigned char *req_hdr; /* REQMOD header */
    unsigned char *res_hdr; /* RESPMOD header */
    const unsigned char *body;
    char *icap_hdr;
    char *payload;
} ic_cl_ctx_t;

typedef struct ic_srv_ctx {
    ic_opts_t opts;
    size_t req_hdr_len;
    size_t res_hdr_len;
    size_t body_len;
    size_t payload_len;
    size_t n_alloc;
    size_t icap_hdr_len;
    uint32_t rc;            /* ICAP return code */
    unsigned char *req_hdr; /* REQMOD header */
    unsigned char *res_hdr; /* RESPMOD header */
    const unsigned char *body;
    char *icap_hdr;
    char *payload;
    unsigned int null_body:1;
    unsigned int got_hdr:1;
} ic_srv_ctx_t;

typedef struct ic_query_int {
    int sd;
    ic_method_t method;
    uint16_t port;
    ic_cl_ctx_t cl;   /* ICAP client context */
    ic_srv_ctx_t srv; /* ICAP server context */
    char *srv_addr;
    char *service;
    char *uri;
    unsigned int hdr_prepared:1; /* All headers prepared */
    unsigned int preview_mode:1;
} ic_query_int_t;

static ic_query_int_t *ic_int_query(ic_query_t *q);
static int ic_create_uri(ic_query_int_t *q);
static int ic_create_header(ic_query_int_t *q);
static int ic_poll_icap(ic_query_int_t *q);
static int ic_send_to_service(ic_query_int_t *q);
static int ic_read_from_service(ic_query_int_t *q);
static int ic_parse_response(ic_query_int_t *q);
static int ic_get_resp_ctx_type(ic_query_int_t *q);

IC_EXPORT const char *ic_err_msg[] = {
    "Unknown error",
    "Bad ICAP server name or IP address",
    "Cannot connect to ICAP server",
    "Socket creation failed",
    "ICAP query structure was not initialized",
    "Cannot allocate memory",
    "Cannot set socket to NONBLOCK mode",
    "Cannot connect to ICAP server: timeout expired",
    "ICAP service is not responding",
    "Cannot get socket options",
    "No events on socket",
    "select(2) error",
    "ICAP request data loss",
    "Error sending ICAP request",
    "Not an ICAP service",
    "End of ICAP header was not found",
    "ICAP/1.0 400 Bad request",
    "Bad header in server response",
    "Internal error: null pointer",
    "Internal error: invalid length",
    "Internal error: integer overflow",
    "Null pointer",
    "Integer overflow",
    "Bad integer value",
    "Cannot get status code from server response",
    "Incorrect ICAP header",
    "Bad request",
    "Cannot get methods list from server response",
    "Connection to ICAP service is closed"
};

IC_EXPORT int ic_query_init(ic_query_t *q)
{
    q->data = calloc(1, sizeof(ic_query_int_t));

    if (!q->data) {
        return -IC_ERR_ENOMEM;
    }

    return 0;
}

IC_EXPORT void ic_query_deinit(ic_query_t *q)
{
    ic_query_int_t *icap = ic_int_query(q);

    if (!icap) {
        return;
    }

    free(icap->service);
    free(icap->uri);
    free(icap->srv_addr);
    free(icap->cl.icap_hdr);
    free(icap->cl.payload);
    free(icap->srv.icap_hdr);
    free(icap->srv.payload);
    free(icap->cl.req_hdr);
    free(icap->cl.res_hdr);
    free(q->data);
}

IC_EXPORT int ic_reuse_connection(ic_query_t *q, int proceed)
{
    ic_query_int_t *icap = ic_int_query(q);

    if (!icap) {
        return -IC_ERR_QUERY_NULL;
    }

    icap->cl.payload_len = 0;
    icap->cl.total_sended = 0;
    icap->srv.payload_len= 0;

    if (!proceed) {
        icap->cl.type = 0;
        icap->cl.body_sended = 0;
        icap->cl.icap_hdr_len = 0;
        icap->hdr_prepared = 0;
        icap->srv.got_hdr = 0;
        icap->srv.null_body = 0;

        IC_FREE(icap->service);
        IC_FREE(icap->uri);
        IC_FREE(icap->cl.icap_hdr);
    }

    IC_FREE(icap->cl.payload);
    IC_FREE(icap->srv.icap_hdr);
    IC_FREE(icap->srv.payload);

    if (icap->sd == -1) {
        return -IC_ERR_CONN_CLOSED;
    }

    return 0;
}

static ic_query_int_t *ic_int_query(ic_query_t *q)
{
    if (q == NULL) {
        return NULL;
    }

    if (q->data == NULL) {
        return NULL;
    }

    return q->data;
}

IC_EXPORT const char *ic_strerror(int err)
{
    int idx = -err; 

    if (err > 0 || idx >= IC_ERR_COUNT) {
        return ic_err_msg[0];
    }

    return ic_err_msg[idx];
}

IC_EXPORT int ic_connect(ic_query_t *q, const char *srv, uint16_t port)
{
    int err = 0;
    int sd, flags, ret;
    fd_set rset, wset;
    struct timeval tv;
    struct sockaddr_in dst;
    ic_query_int_t *icap = ic_int_query(q);

    if (!icap) {
        return -IC_ERR_QUERY_NULL;
    }

    memset(&dst, 0x0, sizeof(dst));

    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    if (inet_pton(AF_INET, srv, &dst.sin_addr.s_addr) != 1) {
        return -IC_ERR_SRV_BADADDR;
    }

    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ) {
        return -IC_ERR_SRV_SOCKET;
    }

    flags = fcntl(sd, F_GETFL, 0);
    if (fcntl(sd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return -IC_ERR_SRV_NONBLOCK;
    }

    if ((connect(sd, (struct sockaddr *) &dst, sizeof(dst)) != 0)
            && (errno != EINPROGRESS)) {
        return -IC_ERR_SRV_CONNECT;
    }

    FD_ZERO(&rset);
    FD_SET(sd, &rset);
    wset = rset;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    ret = select(sd + 1, &rset, &wset, NULL, &tv);
    if (ret == 0) {
        close(sd);
        return -IC_ERR_SRV_TIMEOUT;
    } else if (ret == -1) {
        close(sd);
        return -IC_ERR_SELECT;
    }

    if (FD_ISSET(sd, &rset) || FD_ISSET(sd, &wset)) {
        socklen_t len = sizeof(err);
        if (getsockopt(sd, SOL_SOCKET, SO_ERROR, &err, &len) == -1) {
            close(sd);
            return -IC_ERR_SOCKET_OPTS;
        }
    } else {
        close(sd);
        return -IC_ERR_SOCKET_NO_EVENTS;
    }

    if (err) {
        close(sd);
        return -IC_ERR_SRV_UNREACH;
    }

    icap->sd = sd;
    icap->port = port;
    if ((icap->srv_addr = strdup(srv)) == NULL) {
        return -IC_ERR_ENOMEM;
    }

    return 0;
}

IC_EXPORT int ic_get_options(ic_query_t *q, const char *service)
{
    int err, rc;
    ic_query_int_t *icap = ic_int_query(q);

    if (!icap) {
        return -IC_ERR_QUERY_NULL;
    }

    icap->service = strdup(service);
    icap->method = IC_METHOD_ID_OPTS;

    if (!icap->service) {
        return -IC_ERR_ENOMEM;
    }

    if ((err = ic_create_uri(icap)) != 0) {
        return err;
    }

    if ((err = ic_create_header(icap)) != 0) {
        return err;
    }

    icap->cl.payload = strdup(icap->cl.icap_hdr);
    if (!icap->cl.payload) {
        return -IC_ERR_ENOMEM;
    }

    icap->cl.payload_len = icap->cl.icap_hdr_len;

    if ((rc = ic_poll_icap(icap)) != 0) {
        return rc;
    }

    return 0;
}

IC_EXPORT int ic_set_service(ic_query_t *q, const char *service)
{
    ic_query_int_t *icap = ic_int_query(q);

    if (!icap) {
        return -IC_ERR_QUERY_NULL;
    }

    IC_FREE(icap->service);

    icap->service = strdup(service);

    if (!icap->service) {
        return -IC_ERR_ENOMEM;
    }

    return 0;
}

IC_EXPORT int ic_set_req_hdr(ic_query_t *q, const unsigned char *hdr,
        size_t len)
{
    ic_query_int_t *icap = ic_int_query(q);

    if (!icap) {
        return -IC_ERR_QUERY_NULL;
    }

    if (!hdr) {
        return -IC_ERR_NULL_POINTER;
    }

    IC_FREE(icap->cl.req_hdr);

    icap->cl.req_hdr = malloc(len);
    if (!icap->cl.req_hdr) {
        return -IC_ERR_ENOMEM;
    }

    memcpy(icap->cl.req_hdr, hdr, len);
    icap->cl.req_hdr_len = len;

    return 0;
}

static int ic_get_resp_ctx_type(ic_query_int_t *q)
{
    const char *cl = "\nContent-Length: ";
    const char *te = "\nTransfer-Encoding: chunked";
    int rc = 0;

    ic_substr_t sub = {
        .str = q->cl.res_hdr,
        .sub = cl,
        .str_len = q->cl.res_hdr_len,
        .sub_len = strlen(cl),
        .begin = 0x20, /* space */
        .end   = 0xd   /* \r    */
    };

    if (memmem(q->cl.res_hdr, q->cl.res_hdr_len, te, strlen(te))) {
        q->cl.type = IC_CTX_TYPE_CHUNKED;
        return 0;
    }

    rc = ic_extract_substr(&sub);
    if (rc == 0) {
        if ((rc = ic_strtoul(sub.result, &q->cl.content_len, 10)) != 0) {
            free(sub.result);
            return rc;
        }

        free(sub.result);
        q->cl.type = IC_CTX_TYPE_CL;

        return 0;
    } else if (rc < 0) {
        return rc;
    }

    q->cl.type = IC_CTX_TYPE_CLOSE;

    return 0;
}

IC_EXPORT int ic_set_res_hdr(ic_query_t *q, const unsigned char *hdr,
        size_t len, ic_ctx_type_t *type)
{
    ic_query_int_t *icap = ic_int_query(q);
    int rc;

    if (!icap) {
        return -IC_ERR_QUERY_NULL;
    }

    if (!hdr || !type) {
        return -IC_ERR_NULL_POINTER;
    }

    IC_FREE(icap->cl.res_hdr);

    icap->cl.res_hdr = malloc(len);
    if (!icap->cl.res_hdr) {
        return -IC_ERR_ENOMEM;
    }

    memcpy(icap->cl.res_hdr, hdr, len);
    icap->cl.res_hdr_len = len;

    if ((rc = ic_get_resp_ctx_type(icap)) < 0) {
        return rc;
    }

    *type = rc;

    return 0;
}

IC_EXPORT int ic_set_body(ic_query_t *q, const unsigned char *body,
        size_t len)
{
    ic_query_int_t *icap = ic_int_query(q);

    if (!icap) {
        return -IC_ERR_QUERY_NULL;
    }

    if (!body) {
        return -IC_ERR_NULL_POINTER;
    }

    /* for memory saving just copy body pointer */
    icap->cl.body = body;
    icap->cl.body_len = len;
    icap->cl.payload_len = 0;

    return 0;
}

IC_EXPORT int ic_send_respmod(ic_query_t *q)
{
    int err, rc;
    ic_query_int_t *icap = ic_int_query(q);
    char *p = NULL;
    ic_str_t hex;

    memset(&hex, 0, sizeof(hex));

    if (!icap) {
        return -IC_ERR_QUERY_NULL;
    }

    icap->method = IC_METHOD_ID_RESP;

    if (!icap->cl.icap_hdr_len) {
        if ((err = ic_create_uri(icap)) != 0) {
            return err;
        }

        if ((err = ic_create_header(icap)) != 0) {
            return err;
        }
    }

    if (!icap->hdr_prepared) {
        icap->cl.payload_len = icap->cl.icap_hdr_len +
            icap->cl.req_hdr_len + icap->cl.res_hdr_len;
    }
    icap->cl.payload_len += icap->cl.body_len;

    if (icap->cl.type == IC_CTX_TYPE_CL) {
        if ((rc = ic_str_format_cat(&hex, "%lx\r\n", icap->cl.content_len)) != 0) {
            return rc;
        }

        if (!icap->cl.body_sended) {
            icap->cl.payload_len += hex.len; /* <HEX>\r\n  chunk start */
        }

        if ((icap->cl.body_sended + icap->cl.body_len) == icap->cl.content_len) {
            icap->cl.payload_len += 7;       /* \r\n0\r\n\r\n chunk end */
        }
    }

    IC_FREE(icap->cl.payload);

    if ((icap->cl.payload = malloc(icap->cl.payload_len)) == NULL) {
        return -IC_ERR_ENOMEM;
    }

    p = icap->cl.payload;

    if (!icap->hdr_prepared) {
        memcpy(p, icap->cl.icap_hdr, icap->cl.icap_hdr_len);
        p += icap->cl.icap_hdr_len;
    }

    if (icap->cl.type == IC_CTX_TYPE_CL) {
        if (!icap->hdr_prepared) {
            if (icap->cl.req_hdr_len) {
                memcpy(p, icap->cl.req_hdr, icap->cl.req_hdr_len);
                p += icap->cl.req_hdr_len;
            }

            if (icap->cl.res_hdr_len) {
                memcpy(p, icap->cl.res_hdr, icap->cl.res_hdr_len);
                p += icap->cl.res_hdr_len;
            }
        }

        if (icap->cl.body_len) {
            if (!icap->cl.body_sended) {
                memcpy(p, hex.data, hex.len);
                p += hex.len;
            }

            memcpy(p, icap->cl.body, icap->cl.body_len);

            if ((icap->cl.body_sended + icap->cl.body_len) ==
                    icap->cl.content_len) {
                p += icap->cl.body_len;
                memcpy(p, IC_CRLF IC_CHUNK_IEOF, 7);
            }
        }
    }

    if (!icap->hdr_prepared) {
        icap->hdr_prepared = 1;
    }

    rc = ic_poll_icap(icap);

    ic_str_free(&hex);
    return rc;
}

static int ic_parse_response(ic_query_int_t *q)
{
    size_t len = 0;
    int end_found = 0;
    char *p = q->srv.payload;
    char *str;
    size_t id_len = sizeof(IC_ICAP_ID) - 1;

    if ((q->srv.payload_len < id_len) || memcmp(q->srv.payload, IC_ICAP_ID, id_len) != 0) {
        return -IC_ERR_NON_ICAP;
    }

    for (len = 0; len != q->srv.payload_len; len++, p++) {
        if ((len + 4 <= q->srv.payload_len) && (memcmp(p, IC_RN_TWICE, 4) == 0)) {
            end_found = 1;
            break;
        }
    }

    if (!end_found) {
        return -IC_ERR_HEADER_END;
    }

    q->srv.icap_hdr = calloc(1, len + 1); /* add \0 */
    if (!q->srv.icap_hdr) {
        return -IC_ERR_ENOMEM;
    }

    if (memmem(q->srv.payload, q->srv.payload_len,
                IC_NULL_BODY, sizeof(IC_NULL_BODY) - 1)) {
        q->srv.null_body = 1;
    }

    memcpy(q->srv.icap_hdr, q->srv.payload, len);
    q->srv.icap_hdr_len = len + 4; /* + \r\n\r\n */

    /* Get ICAP status code */
    if ((str = strstr(q->srv.icap_hdr, IC_ICAP_ID)) != NULL) {
        char *start, *end;
        size_t space = 0;

        while (*str) {
            if ((*str == 0x20) && !space && (*(str + 1) != '\0')) {
                start = str + 1;
                space++;
            } else if ((*str == 0x20) && space) {
                end = str;
                space++;
                break;
            }

            str++;
        }

        if (space == 2) {
            int rc;
            char *status;
            size_t slen = end - start;

            if ((status = calloc(1, slen + 1)) == NULL) {
                return -IC_ERR_ENOMEM;
            }

            memcpy(status, start, slen);

            if ((rc = ic_strtoui(status, &q->srv.rc, 10)) != 0) {
                free(status);
                return rc;
            }

            free(status);
        } else {
            return -IC_ERR_STATUS_NOT_FOUND;
        }
    } else {
        return -IC_ERR_BAD_HEADER;
    }

    if (q->method == IC_METHOD_ID_OPTS && q->srv.rc != IC_CODE_OK) {
        switch (q->srv.rc) {
        case IC_CODE_BAD_REQUEST:
            return -IC_ERR_BAD_REQUEST;
        default:
            return -IC_ERR_COUNT;
        }
    }

    /* Get ICAP options */
    if (q->method == IC_METHOD_ID_OPTS) {
        /* RFC-3507: Field names are case-insensitive. */
        if ((str = strcasestr(q->srv.icap_hdr, "\nMethods: "))) {
            if (strstr(str, "RESPMOD")) {
                q->srv.opts.m_resp = 1;
            }
            if (strstr(str, "REQMOD")) {
                q->srv.opts.m_req = 1;
            }
        } else {
            return -IC_ERR_METHODS_NOT_FOUND;
        }

        if ((str = strcasestr(q->srv.icap_hdr, "\nAllow: "))) {
            if (strstr(str, "204")) {
                q->srv.opts.allow_204 = 1;
            }
        }

        if ((str = strcasestr(q->srv.icap_hdr, "\nPreview: "))) {
            int rc;
            size_t plen;
            char *start, *end, *preview;

            while (*str) {
                if (*str == 0x20 && *(str + 1) != '\0') {
                    start = str + 1;
                }
                if (*str == '\r') {
                    end = str;
                    break;
                }
                str++;
            }

            plen = end - start;
            if ((preview = calloc(1, plen + 1)) == NULL) {
                return -IC_ERR_ENOMEM;
            }

            memcpy(preview, start, plen);

            if ((rc = ic_strtoui(preview, &q->srv.opts.preview_len, 10)) != 0) {
                free(preview);
                return rc;
            }

            free(preview);
        }
    }

    return 0;
}

static int ic_create_uri(ic_query_int_t *q)
{
    if (asprintf(&q->uri, "icap://%s:%u/%s",
                q->srv_addr, q->port, q->service) == -1) {
        return -IC_ERR_ENOMEM;
    }

    return 0;
}

/* RFC-3507 The "Encapsulated" Header:
 * REQMOD request encapsulated_list: [reqhdr] reqbody
 * REQMOD response encapsulated_list: {[reqhdr] reqbody} |
 * {[reshdr] resbody}
 * RESPMOD request encapsulated_list: [reqhdr] [reshdr] resbody
 * RESPMOD response encapsulated_list: [reshdr] resbody
 * OPTIONS response encapsulated_list: optbody
 */
static int ic_create_header(ic_query_int_t *q)
{
    switch (q->method) {

    case IC_METHOD_ID_OPTS:
        if ((q->cl.icap_hdr_len = asprintf(&q->cl.icap_hdr, "%s %s %s\r\n%s%s",
                    IC_METHOD_OPTIONS, q->uri, IC_ICAP_ID,
                    IC_NULL_BODY, IC_RN_TWICE)) == -1) {
            return -IC_ERR_ENOMEM;
        }
        break;

    case IC_METHOD_ID_RESP:
        {
            ic_str_t enca;
            int rc = 0;

            memset(&enca, 0, sizeof(enca));

            if (q->cl.req_hdr_len) { /* req hdr exists */
                rc += ic_str_format_cat(&enca, "Encapsulated: req-hdr=0");
                if (q->cl.res_hdr_len) { /* res hdr exists */
                    rc += ic_str_format_cat(&enca, ", res-hdr=%zu", q->cl.req_hdr_len);
                    if (q->cl.body_len) { /* body exists */
                        rc += ic_str_format_cat(&enca, ", res-body=%zu", q->cl.res_hdr_len);
                    } else { /*no body */
                        rc += ic_str_format_cat(&enca, ", null-body=%zu", q->cl.res_hdr_len);
                    }
                } else { /* no res hdr */
                    if (q->cl.body_len) { /* body exists */
                        rc += ic_str_format_cat(&enca, ", res-body=0");
                    } else { /*no body */
                        rc += ic_str_format_cat(&enca, ", null-body=0");
                    }
                }
            } else { /* no req hrd */
                if (q->cl.res_hdr_len) { /* res hdr exists */
                    rc += ic_str_format_cat(&enca, "Encapsulated: res-hdr=0");
                    if (q->cl.body_len) { /* body exists */
                        rc += ic_str_format_cat(&enca, ", res-body=%zu", q->cl.res_hdr_len);
                    } else { /*no body */
                        rc += ic_str_format_cat(&enca, ", null-body=%zu", q->cl.res_hdr_len);
                    }
                } else { /* no res hdr */
                    if (q->cl.body_len) { /* body exists */
                        rc += ic_str_format_cat(&enca, ", res-body=0");
                    } else { /*no body */
                        rc += ic_str_format_cat(&enca, ", null-body=0");
                    }
                }
            }

            if (rc != 0) {
                return -IC_ERR_ENOMEM;
            }

            if ((q->cl.icap_hdr_len = asprintf(&q->cl.icap_hdr, "%s %s %s\r\n%s%s",
                        IC_METHOD_RESPMOD, q->uri, IC_ICAP_ID,
                        enca.data, IC_RN_TWICE)) == -1) {
                return -IC_ERR_ENOMEM;
            }

            ic_str_free(&enca);
        }
        break;

    case IC_METHOD_ID_REQ:
        break;
    }

    return 0;
}

static int ic_poll_icap(ic_query_int_t *q)
{
    int rc = 0, done = 0, send_done = 0;
    fd_set rset, wset;
    struct timeval tv;

    tv.tv_sec = 60;
    tv.tv_usec = 0;

    q->srv.n_alloc = IC_SRV_ALLOC_LEN;
    if ((q->srv.payload = calloc(1, q->srv.n_alloc)) == NULL) {
        return -IC_ERR_ENOMEM;
    }

    while (!done) {
        FD_ZERO(&rset);
        FD_ZERO(&wset);
        FD_SET(q->sd, &rset);

        if (!send_done) {
            wset = rset;
        };

        /* TODO use exceptfds too */
        rc = select(q->sd + 1, &rset, &wset, NULL, &tv);
        switch (rc) {
        case -1:
            return -IC_ERR_SELECT;
        case 0:
            return -IC_ERR_SRV_TIMEOUT;
        default:
            if (FD_ISSET(q->sd, &rset)) {
                printf(">>> read\n");
                rc = ic_read_from_service(q);

                switch (rc) {
                case 0: /* read done */
                    printf(">>> read done\n");
                    done = 1;
                    break;
                case 1: /* read more */
                    printf(">>> read more\n");
                    break;
                default: /* read error */
                    printf(">>> read error\n");
                    return rc;
                }
            }

            if (FD_ISSET(q->sd, &wset)) {
                printf(">>> write\n");
                rc = ic_send_to_service(q);

                switch (rc) {
                case 0: /* write done */
                    printf(">>> write done\n");
                    send_done = 1;
                    break;
                case 1: /* do not need to read */
                    printf(">>> do not need to read\n");
                    done = 1;
                    break;
                case 2: /* write more */
                    printf(">>> write more\n");
                    break;
                default:
                    return rc;
                }
            }
        }
    }

    return rc;
}

static int ic_send_to_service(ic_query_int_t *q)
{
    ssize_t sended = 0;

    do {
        sended = send(q->sd, q->cl.payload + q->cl.total_sended,
                q->cl.payload_len - q->cl.total_sended, 0);

        if (sended > 0) {
            q->cl.total_sended += sended;
        }

        if (sended < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
            return -IC_ERR_SEND;
        }
    } while (sended > 0);

    /* All payload was sended but not all content available now */
    if (q->cl.type == IC_CTX_TYPE_CL) {
        if (q->cl.total_sended == q->cl.payload_len) {
            q->cl.body_sended += q->cl.body_len;

            /* Do now wait for the ICAP server response if not all chunk data sended */
            if (q->cl.body_sended != q->cl.content_len) {
                return 1;
            }
        }
    }

    /* Not all payload was sended, wait for select(2) writefds available */
    if (q->cl.total_sended != q->cl.payload_len) {
        return 2;
    }

    return 0;
}

static int ic_read_from_service(ic_query_int_t *q)
{
    ssize_t nread;
    int rc = 1;

    do {
        if (q->srv.payload_len + IC_SRV_READ_LEN >= q->srv.n_alloc) {
            q->srv.n_alloc *= 2;
            void *tmp = realloc(q->srv.payload, q->srv.n_alloc);
            if (!tmp) {
                free(q->srv.payload);
                return -IC_ERR_ENOMEM;
            }

            q->srv.payload = tmp;
        }

        nread = read(q->sd, q->srv.payload + q->srv.payload_len, IC_SRV_READ_LEN);
        if (nread > 0) {
            q->srv.payload_len += nread;
        }
        printf("read data %zd, total:%zd\n", nread, q->srv.payload_len);

        if (nread < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
            return -IC_ERR_SEND;
        } else if (nread < 0) {
            break;
        }
    } while (nread > 0);

    /* XXX what if we do not get ICAP header now, only part of it ? */
    if (!q->srv.got_hdr) {
        int n = 0;
        if ((n = ic_parse_response(q)) != 0) {
            return n;
        }
        printf("got ICAP header\n");
        q->srv.got_hdr = 1;
    }

    if (q->srv.null_body) {
        printf("got NULL body\n");
        rc = 0;
    } else {
        /* check for zero chunk */
        if (q->srv.payload_len > 7) {
            if (!memcmp(q->srv.payload + q->srv.payload_len - 7,
                        IC_CRLF IC_CHUNK_IEOF , 7)) {
                printf("zero chunk found\n");
                rc = 0;
            }
        }
    }

    return rc;
}

IC_EXPORT void ic_disconnect(ic_query_t *q)
{
    ic_query_int_t *icap = ic_int_query(q);

    close(icap->sd);
    icap->sd = -1;
}

IC_EXPORT const char *ic_get_icap_hdr(ic_query_t *q)
{
    ic_query_int_t *icap = ic_int_query(q);

    if (!icap) {
        return NULL;
    }

    return icap->srv.icap_hdr;
}

IC_EXPORT const char *ic_get_content(ic_query_t *q, size_t *len)
{
    ic_query_int_t *icap = ic_int_query(q);

    if (!icap || !len) {
        return NULL;
    }

    *len = icap->srv.payload_len;

    return icap->srv.payload;
}
