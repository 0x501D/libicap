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

#define IC_EXPORT __attribute__((visibility ("default")))
#define IC_ICAP_ID "ICAP/1.0"
#define IC_METHOD_REQMOD  "REQMOD"
#define IC_METHOD_RESPMOD "RESPMOD"
#define IC_METHOD_OPTIONS "OPTIONS"
#define IC_CHUNK_TERM "0\r\n\r\n"
#define IC_RN_TWICE "\r\n\r\n"
#define IC_SRV_ALLOC_SIZE 2048

typedef struct ic_query {
    void *data;
} ic_query_t;

typedef struct ic_query_int {
    int sd;
    uint16_t port;
    size_t cl_data_len;
    size_t srv_data_len;
    char *srv;
    char *service;
    char *uri;
    char *cl_header;
    char *cl_data;
    char *srv_header;
    char *srv_data;
} ic_query_int_t;

ic_query_int_t *ic_int_query(ic_query_t *q);
int ic_create_uri(ic_query_int_t *q);
int ic_create_header(ic_query_int_t *q, const char *method);
int ic_poll_icap(ic_query_int_t *q);
int ic_send_to_service(ic_query_int_t *q);
int ic_read_from_service(ic_query_int_t *q);
int ic_parse_header(ic_query_int_t *q);

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
    "Not an ICAP service"
};

enum {
    IC_ERR_SRV_BADADDR = 1,
    IC_ERR_SRV_CONNECT,
    IC_ERR_SRV_SOCKET,
    IC_ERR_QUERY_NULL,
    IC_ERR_ENOMEM,
    IC_ERR_SRV_NONBLOCK,
    IC_ERR_SRV_TIMEOUT,
    IC_ERR_SRV_UNREACH,
    IC_ERR_SOCKET_OPTS,
    IC_ERR_SOCKET_NO_EVENTS,
    IC_ERR_SELECT,
    IC_ERR_SEND_PARTED,
    IC_ERR_SEND,
    IC_ERR_NON_ICAP,
    IC_ERR_COUNT
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
    free(icap->cl_header);
    free(icap->cl_data);
    free(icap->srv_header);
    free(icap->srv_data);
    free(q->data);
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

    if (err > 0 || idx > IC_ERR_COUNT) {
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

IC_EXPORT int ic_send_query(ic_query_t *q)
{
    return 0;
}

IC_EXPORT int ic_get_options(ic_query_t *q)
{
    int err, rc;
    ic_query_int_t *icap = ic_int_query(q);

    if (!icap) {
        return -IC_ERR_QUERY_NULL;
    }

    if (!icap->uri) {
        if ((err = ic_create_uri(icap)) != 0) {
            return err;
        }

        if ((err = ic_create_header(icap, IC_METHOD_OPTIONS)) != 0) {
            return err;
        }

        icap->cl_data = strdup(icap->cl_header);
        if (!icap->cl_data) {
            return -IC_ERR_ENOMEM;
        }

        icap->cl_data_len = strlen(icap->cl_data);
    }

    if ((rc = ic_poll_icap(icap)) != 0) {
        return rc;
    }

    if ((rc = ic_parse_header(icap)) != 0) {
        return rc;
    }

    return 0;
}

int ic_parse_header(ic_query_int_t *q)
{
    size_t len = 0;
    char *p = q->srv_data;
    size_t id_len = sizeof(IC_ICAP_ID) - 1;

    if ((q->srv_data_len < id_len) || memcmp(q->srv_data, IC_ICAP_ID, id_len) != 0) {
        return -IC_ERR_NON_ICAP;
    }

    for (len = 0; len != q->srv_data_len; len++, p++) {
        if ((len + 4 <= q->srv_data_len) && (memcmp(p, IC_RN_TWICE, 4) == 0)) {
            break;
        }
    }

    q->srv_header = calloc(1, len + 1);
    if (!q->srv_header) {
        return -IC_ERR_ENOMEM;
    }

    memcpy(q->srv_header, q->srv_data, len);

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
    if (asprintf(&q->cl_header, "%s %s %s\r\n%s%s",
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

IC_EXPORT int ic_set_service(ic_query_t *q, const char *service)
{
    ic_query_int_t *icap = ic_int_query(q);

    if (!icap) {
        return -IC_ERR_QUERY_NULL;
    }

    if (icap->service) {
        free(icap->service);
        free(icap->uri);
        free(icap->cl_header);
        free(icap->cl_data);
    }

    icap->service = strdup(service);

    if (!icap->service) {
        return -IC_ERR_ENOMEM;
    }

    return 0;
}

IC_EXPORT const char *ic_get_icap_header(ic_query_t *q)
{
    ic_query_int_t *icap = ic_int_query(q);

    if (!icap) {
        return NULL;
    }

    return icap->srv_header;
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
