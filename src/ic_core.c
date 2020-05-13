#define _GNU_SOURCE /* asprintf(3) */
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

enum {
    IC_METHOD_ID_REQ,
    IC_METHOD_ID_RESP,
    IC_METHOD_ID_OPTS
};

typedef struct ic_opts {
    uint32_t preview_len;
    unsigned int allow_204:1;
    unsigned int m_resp:1;
    unsigned int m_req:1;
} ic_opts_t;

typedef struct ic_query_int {
    int sd;
    int type;
    uint32_t rc;
    uint16_t port;
    ic_opts_t opts_cl;
    ic_opts_t opts_srv;
    size_t cl_data_len;
    size_t srv_data_len;
    char *srv;
    char *service;
    char *uri;
    char *cl_icap_header;
    char *cl_data;
    char *srv_icap_header;
    char *srv_data;
} ic_query_int_t;

ic_query_int_t *ic_int_query(ic_query_t *q);
int ic_create_uri(ic_query_int_t *q);
int ic_create_header(ic_query_int_t *q, const char *method);
int ic_poll_icap(ic_query_int_t *q);
int ic_send_to_service(ic_query_int_t *q);
int ic_read_from_service(ic_query_int_t *q);
int ic_parse_header(ic_query_int_t *q, int method);
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
    free(icap->cl_icap_header);
    free(icap->cl_data);
    free(icap->srv_icap_header);
    free(icap->srv_data);
    free(q->data);
}

void ic_query_clean(ic_query_int_t *q)
{
    q->cl_data_len = 0;
    q->srv_data_len = 0;
    IC_FREE(q->service);
    IC_FREE(q->uri);
    IC_FREE(q->srv);
    IC_FREE(q->cl_icap_header);
    IC_FREE(q->cl_data);
    IC_FREE(q->srv_icap_header);
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

    if (!icap->service) {
        return -IC_ERR_ENOMEM;
    }

    if ((err = ic_create_uri(icap)) != 0) {
        return err;
    }

    if ((err = ic_create_header(icap, IC_METHOD_OPTIONS)) != 0) {
        return err;
    }

    icap->cl_data = strdup(icap->cl_icap_header);
    if (!icap->cl_data) {
        return -IC_ERR_ENOMEM;
    }

    icap->cl_data_len = strlen(icap->cl_data);

    if ((rc = ic_poll_icap(icap)) != 0) {
        return rc;
    }

    if ((rc = ic_parse_header(icap, IC_METHOD_ID_OPTS)) != 0) {
        return rc;
    }

    return 0;
}

IC_EXPORT int ic_send_respmod(ic_query_t *q, ic_data_t *resp)
{
    return 0;
}

int ic_parse_header(ic_query_int_t *q, int method)
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

    q->srv_icap_header = calloc(1, len + 1);
    if (!q->srv_icap_header) {
        return -IC_ERR_ENOMEM;
    }

    memcpy(q->srv_icap_header, q->srv_data, len);

    /* Get ICAP status code */
    if ((str = strstr(q->srv_icap_header, IC_ICAP_ID)) != NULL) {
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
        if ((str = strcasestr(q->srv_icap_header, "\nMethods: "))) {
            if (strstr(str, "RESPMOD")) {
                q->opts_srv.m_resp = 1;
            }
            if (strstr(str, "REQMOD")) {
                q->opts_srv.m_req = 1;
            }
        } else {
            return -IC_ERR_METHODS_NOT_FOUND;
        }

        if ((str = strcasestr(q->srv_icap_header, "\nAllow: "))) {
            if (strstr(str, "204")) {
                q->opts_srv.allow_204 = 1;
            }
        }

        if ((str = strcasestr(q->srv_icap_header, "\nPreview: "))) {
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

int ic_create_header(ic_query_int_t *q, const char *method)
{
    if (asprintf(&q->cl_icap_header, "%s %s %s\r\n%s%s",
                method, q->uri, IC_ICAP_ID,
                "Encapsulated: null-body=0", IC_RN_TWICE) == -1) {
        return -IC_ERR_ENOMEM;
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

    return icap->srv_icap_header;
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
