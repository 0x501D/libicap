#define _GNU_SOURCE /* asprintf(3), memmem(3) */
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
#include "ic_core.h"
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

typedef struct ic_ctx {
    ic_ctx_type_t type;
    size_t req_hdr_len;
    size_t res_hdr_len;
    size_t body_len;
    uint32_t content_len;
    unsigned char *req_hdr;
    unsigned char *res_hdr;
    const unsigned char *body;
} ic_ctx_t;

typedef struct ic_query_int {
    int sd;
    ic_method_t method;
    uint32_t rc;
    uint16_t port;
    ic_opts_t opts_cl;
    ic_opts_t opts_srv;
    ic_ctx_t ctx;
    size_t cl_data_len;
    size_t srv_data_len;
    int cl_icap_hdr_len;
    char *srv;
    char *service;
    char *uri;
    char *cl_icap_hdr;
    char *cl_data;
    char *srv_icap_hdr;
    char *srv_data;
    unsigned int hdr_sent:1;
    unsigned int preview_mode:1;
} ic_query_int_t;

ic_query_int_t *ic_int_query(ic_query_t *q);
int ic_create_uri(ic_query_int_t *q);
int ic_create_header(ic_query_int_t *q);
int ic_poll_icap(ic_query_int_t *q);
int ic_send_to_service(ic_query_int_t *q);
int ic_read_from_service(ic_query_int_t *q);
int ic_parse_response(ic_query_int_t *q, int method);
ic_ctx_type_t ic_get_resp_ctx_type(ic_query_int_t *q);
void ic_query_clean(ic_query_int_t *q);

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
    "Cannot get methods list from server response"
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
    free(icap->srv);
    free(icap->cl_icap_hdr);
    free(icap->cl_data);
    free(icap->srv_icap_hdr);
    free(icap->srv_data);
    free(q->data);
}

void ic_query_clean(ic_query_int_t *q)
{
    q->cl_data_len = 0;
    q->cl_icap_hdr_len = 0;
    q->srv_data_len = 0;
    IC_FREE(q->service);
    IC_FREE(q->uri);
    IC_FREE(q->cl_icap_hdr);
    IC_FREE(q->cl_data);
    IC_FREE(q->srv_icap_hdr);
    IC_FREE(q->srv_data);
}

ic_query_int_t *ic_int_query(ic_query_t *q)
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
    if ((icap->srv = strdup(srv)) == NULL) {
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

    ic_query_clean(icap);
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

    icap->cl_data = strdup(icap->cl_icap_hdr);
    if (!icap->cl_data) {
        return -IC_ERR_ENOMEM;
    }

    icap->cl_data_len = icap->cl_icap_hdr_len;

    if ((rc = ic_poll_icap(icap)) != 0) {
        return rc;
    }

    if ((rc = ic_parse_response(icap, IC_METHOD_ID_OPTS)) != 0) {
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

    ic_query_clean(icap);
    if (icap->service) {
        IC_FREE(icap->service);
        //XXX q->cl_icap_hdr_len = 0;
        //...
    }

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

    if (icap->ctx.req_hdr) {
        IC_FREE(icap->ctx.req_hdr);
    }

    icap->ctx.req_hdr = malloc(len);
    if (!icap->ctx.req_hdr) {
        return -IC_ERR_ENOMEM;
    }

    memcpy(icap->ctx.req_hdr, hdr, len);
    icap->ctx.req_hdr_len = len;

    return 0;
}

ic_ctx_type_t ic_get_resp_ctx_type(ic_query_int_t *q)
{
    const char *cl = "\nContent-Length: ";
    const char *te = "\nTransfer-Encoding: chunked";
    void *clp = NULL;

    clp = memmem(q->ctx.res_hdr, q->ctx.res_hdr_len, cl, strlen(cl));
    if (clp) {
        /* Get Content-Length value */
        int rc = 0;
        char *p = (char *) clp;
        size_t cl_buf_len = 0;
        size_t cl_offset = (unsigned char *) clp - q->ctx.res_hdr;
        size_t cl_rest = q->ctx.res_hdr_len - cl_offset;
        char *cl_buf;
        char *start = NULL, *end = NULL;

        for (size_t n = 0; n < cl_rest; n++, p++) {
            char ch = *p;

            if (ch == 0x20) {
                start = p + 1;
            }

            if (ch == 0xd) {
                end = p;
                cl_buf_len = end - start;

                if ((cl_buf = calloc(1, cl_buf_len + 1)) == NULL) {
                    return -IC_ERR_ENOMEM;
                }

                memcpy(cl_buf, start, cl_buf_len);
                if ((rc = ic_strtoui(cl_buf, &q->ctx.content_len, 10)) != 0) {
                    free(cl_buf);
                    return rc;
                }

                free(cl_buf);
                break;
            }
        }

        return IC_CTX_TYPE_CL;
    }

    if (memmem(q->ctx.res_hdr, q->ctx.res_hdr_len, te, strlen(te))) {
        return IC_CTX_TYPE_CHUNKED;
    }

    return IC_CTX_TYPE_CLOSE;
}

IC_EXPORT int ic_set_res_hdr(ic_query_t *q, const unsigned char *hdr,
        size_t len, ic_ctx_type_t *type)
{
    ic_query_int_t *icap = ic_int_query(q);

    if (!icap) {
        return -IC_ERR_QUERY_NULL;
    }

    if (!hdr || !type) {
        return -IC_ERR_NULL_POINTER;
    }

    if (icap->ctx.res_hdr) {
        IC_FREE(icap->ctx.res_hdr);
    }

    icap->ctx.res_hdr = malloc(len);
    if (!icap->ctx.res_hdr) {
        return -IC_ERR_ENOMEM;
    }

    memcpy(icap->ctx.res_hdr, hdr, len);
    icap->ctx.res_hdr_len = len;
    icap->ctx.type = *type = ic_get_resp_ctx_type(icap);

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
    icap->ctx.body = body;
    icap->ctx.body_len = len;

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

    if (!icap->cl_icap_hdr_len) {
        if ((err = ic_create_uri(icap)) != 0) {
            return err;
        }

        if ((err = ic_create_header(icap)) != 0) {
            return err;
        }
    }

    if (!icap->hdr_sent) {
        icap->cl_data_len = icap->cl_icap_hdr_len;
    }
    icap->cl_data_len += icap->ctx.req_hdr_len +
        icap->ctx.res_hdr_len + icap->ctx.body_len;

    if (icap->ctx.type == IC_CTX_TYPE_CL) {
        size_t chunk_len = 0;
        int rc;

        if ((rc = ic_str_format_cat(&hex, "%x\r\n", icap->ctx.content_len)) != 0) {
            return rc;
        }

        chunk_len += hex.len; /* <HEX>\r\n  chunk start */
        chunk_len += 7;       /* \r\n0\r\n\r\n chunk end */
        icap->cl_data_len += chunk_len;
    }

    if ((icap->cl_data = malloc(icap->cl_data_len)) == NULL) {
        return -IC_ERR_ENOMEM;
    }

    p = icap->cl_data;

    if (!icap->hdr_sent) {
        memcpy(p, icap->cl_icap_hdr, icap->cl_icap_hdr_len);
        p += icap->cl_icap_hdr_len;
    }

    if (icap->ctx.type == IC_CTX_TYPE_CL) {
        if (icap->ctx.req_hdr_len) {
            memcpy(p, icap->ctx.req_hdr, icap->ctx.req_hdr_len);
            p += icap->ctx.req_hdr_len;
        }

        if (icap->ctx.res_hdr_len) {
            memcpy(p, icap->ctx.res_hdr, icap->ctx.res_hdr_len);
            p += icap->ctx.res_hdr_len;
        }

        if (icap->ctx.body_len) {
            memcpy(p, hex.data, hex.len);
            p += hex.len;

            memcpy(p, icap->ctx.body, icap->ctx.body_len);
            p += icap->ctx.body_len;

            memcpy(p, IC_CRLF IC_CHUNK_IEOF, 7);
        }
    }

    if ((rc = ic_poll_icap(icap)) != 0) {
        return rc;
    }

    ic_str_free(&hex);

    return 0;
}

int ic_parse_response(ic_query_int_t *q, int method)
{
    size_t len = 0;
    int end_found = 0;
    char *p = q->srv_data;
    char *str;
    size_t id_len = sizeof(IC_ICAP_ID) - 1;

    if ((q->srv_data_len < id_len) || memcmp(q->srv_data, IC_ICAP_ID, id_len) != 0) {
        return -IC_ERR_NON_ICAP;
    }

    for (len = 0; len != q->srv_data_len; len++, p++) {
        if ((len + 4 <= q->srv_data_len) && (memcmp(p, IC_RN_TWICE, 4) == 0)) {
            end_found = 1;
            break;
        }
    }

    if (!end_found) {
        return -IC_ERR_HEADER_END;
    }

    q->srv_icap_hdr = calloc(1, len + 1);
    if (!q->srv_icap_hdr) {
        return -IC_ERR_ENOMEM;
    }

    memcpy(q->srv_icap_hdr, q->srv_data, len);

    /* Get ICAP status code */
    if ((str = strstr(q->srv_icap_hdr, IC_ICAP_ID)) != NULL) {
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

            if ((rc = ic_strtoui(status, &q->rc, 10)) != 0) {
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

    if (method == IC_METHOD_ID_OPTS && q->rc != IC_CODE_OK) {
        switch (q->rc) {
        case IC_CODE_BAD_REQUEST:
            return -IC_ERR_BAD_REQUEST;
        default:
            return -IC_ERR_COUNT;
        }
    }

    /* Get ICAP options */
    if (method == IC_METHOD_ID_OPTS) {
        /* RFC-3507: Field names are case-insensitive. */
        if ((str = strcasestr(q->srv_icap_hdr, "\nMethods: "))) {
            if (strstr(str, "RESPMOD")) {
                q->opts_srv.m_resp = 1;
            }
            if (strstr(str, "REQMOD")) {
                q->opts_srv.m_req = 1;
            }
        } else {
            return -IC_ERR_METHODS_NOT_FOUND;
        }

        if ((str = strcasestr(q->srv_icap_hdr, "\nAllow: "))) {
            if (strstr(str, "204")) {
                q->opts_srv.allow_204 = 1;
            }
        }

        if ((str = strcasestr(q->srv_icap_hdr, "\nPreview: "))) {
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

            if ((rc = ic_strtoui(preview, &q->opts_srv.preview_len, 10)) != 0) {
                free(preview);
                return rc;
            }

            free(preview);
        }
    }

    return 0;
}

int ic_create_uri(ic_query_int_t *q)
{
    if (asprintf(&q->uri, "icap://%s:%u/%s",
                q->srv, q->port, q->service) == -1) {
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
int ic_create_header(ic_query_int_t *q)
{
    switch (q->method) {

    case IC_METHOD_ID_OPTS:
        if ((q->cl_icap_hdr_len = asprintf(&q->cl_icap_hdr, "%s %s %s\r\n%s%s",
                    IC_METHOD_OPTIONS, q->uri, IC_ICAP_ID,
                    "Encapsulated: null-body=0", IC_RN_TWICE)) == -1) {
            return -IC_ERR_ENOMEM;
        }
        break;

    case IC_METHOD_ID_RESP:
        {
            ic_str_t enca;
            int rc = 0;

            memset(&enca, 0, sizeof(enca));

            if (q->ctx.req_hdr_len) { /* req hdr exists */
                rc += ic_str_format_cat(&enca, "Encapsulated: req-hdr=0");
                if (q->ctx.res_hdr_len) { /* res hdr exists */
                    rc += ic_str_format_cat(&enca, ", res-hdr=%zu", q->ctx.req_hdr_len);
                    if (q->ctx.body_len) { /* body exists */
                        rc += ic_str_format_cat(&enca, ", res-body=%zu", q->ctx.res_hdr_len);
                    } else { /*no body */
                        rc += ic_str_format_cat(&enca, ", null-body=%zu", q->ctx.res_hdr_len);
                    }
                } else { /* no res hdr */
                    if (q->ctx.body_len) { /* body exists */
                        rc += ic_str_format_cat(&enca, ", res-body=0");
                    } else { /*no body */
                        rc += ic_str_format_cat(&enca, ", null-body=0");
                    }
                }
            } else { /* no req hrd */
                if (q->ctx.res_hdr_len) { /* res hdr exists */
                    rc += ic_str_format_cat(&enca, "Encapsulated: res-hdr=0");
                    if (q->ctx.body_len) { /* body exists */
                        rc += ic_str_format_cat(&enca, ", res-body=%zu", q->ctx.res_hdr_len);
                    } else { /*no body */
                        rc += ic_str_format_cat(&enca, ", null-body=%zu", q->ctx.res_hdr_len);
                    }
                } else { /* no res hdr */
                    if (q->ctx.body_len) { /* body exists */
                        rc += ic_str_format_cat(&enca, ", res-body=0");
                    } else { /*no body */
                        rc += ic_str_format_cat(&enca, ", null-body=0");
                    }
                }
            }

            /*if (rc != 0) {
                return -IC_ERR_ENOMEM;
            }*/

            if ((q->cl_icap_hdr_len = asprintf(&q->cl_icap_hdr, "%s %s %s\r\n%s%s",
                        IC_METHOD_RESPMOD, q->uri, IC_ICAP_ID,
                        enca.data, IC_RN_TWICE)) == -1) {
                return -IC_ERR_ENOMEM;
            }

            printf("'%s'\n", q->cl_icap_hdr);

            ic_str_free(&enca);
        }
        break;

    case IC_METHOD_ID_REQ:
        break;
    }

    return 0;
}

int ic_poll_icap(ic_query_int_t *q)
{
    int rc = 0, done = 0, send_done = 0;
    fd_set rset, wset;
    struct timeval tv;

    tv.tv_sec = 1;
    tv.tv_usec = 0;

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
                //printf("read data\n");
                if ((rc = ic_read_from_service(q)) == 0) {
                    done = 1;
                } else {
                    return rc;
                }
            }

            if (FD_ISSET(q->sd, &wset)) {
                //printf("send data\n");
                if ((rc = ic_send_to_service(q)) == 0) {
                    send_done = 1;
                } else {
                    return rc;
                }
            }
        }
    }

    return rc;
}

int ic_send_to_service(ic_query_int_t *q)
{
    ssize_t sended = 0;
    size_t total_sended = 0;

    do {
        sended = send(q->sd, q->cl_data + total_sended, q->cl_data_len - total_sended, 0);

        if (sended < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
            return -IC_ERR_SEND;
        }
        total_sended += sended;
    } while (sended > 0);

    if (total_sended != q->cl_data_len) {
        return -IC_ERR_SEND_PARTED;
    }

    return 0;
}

int ic_read_from_service(ic_query_int_t *q)
{
    ssize_t nread;
    size_t total_read = 0;
    size_t n_alloc = IC_SRV_ALLOC_SIZE;

    if ((q->srv_data = calloc(1, n_alloc)) == NULL) {
        return -IC_ERR_ENOMEM;
    }

    do {
        if (total_read >= IC_SRV_ALLOC_SIZE) {
            n_alloc += IC_SRV_ALLOC_SIZE;
            void *tmp = realloc(q->srv_data, n_alloc);
            if (!tmp) {
                free(q->srv_data);
                return -IC_ERR_ENOMEM;
            }

            q->srv_data = tmp;
        }

        nread  = read(q->sd, q->srv_data, IC_SRV_ALLOC_SIZE);

        if (nread < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
            return -IC_ERR_SEND;
        } else if (nread < 0) {
            break;
        }
        total_read += nread;
    } while (nread > 0);

    q->srv_data_len = total_read;

    return 0;
}

IC_EXPORT void ic_disconnect(ic_query_t *q)
{
    ic_query_int_t *icap = ic_int_query(q);

    close(icap->sd);
}

IC_EXPORT const char *ic_get_icap_header(ic_query_t *q)
{
    ic_query_int_t *icap = ic_int_query(q);

    if (!icap) {
        return NULL;
    }

    return icap->srv_icap_hdr;
}

IC_EXPORT const char *ic_get_content(ic_query_t *q, size_t *len)
{
    ic_query_int_t *icap = ic_int_query(q);

    if (!icap || !len) {
        return NULL;
    }

    *len = icap->srv_data_len;

    return icap->srv_data;
}
