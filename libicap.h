#ifndef LIBICAP_H_
#define LIBICAP_H_

#include <stdint.h>

#ifdef _cplusplus
extern "C" {
#endif

typedef struct ic_query {
    void *data;
} ic_query_t;

typedef enum ic_ctx_type {
    IC_CTX_TYPE_CLOSE,   /* objects arriving using a TCP close              */
    IC_CTX_TYPE_CHUNKED, /* objects arriving using chunked encoding         */
    IC_CTX_TYPE_CL,      /* objects arriving using "Content-Length" headers */
} ic_ctx_type_t;

int ic_query_init(ic_query_t *q);
int ic_connect(ic_query_t *q, const char *srv, uint16_t port);
int ic_get_options(ic_query_t *q, const char *service);
int ic_send_respmod(ic_query_t *q);
int ic_send_reqmod(ic_query_t *q);

int ic_set_service(ic_query_t *q, const char *service);
int ic_set_req_hdr(ic_query_t *q, const unsigned char *hdr, size_t len);
int ic_set_res_hdr(ic_query_t *q, const unsigned char *hdr, size_t len, ic_ctx_type_t *type);

/* body will not be copyed, do not free it before using ic_send_(resp|req)mod() */
int ic_set_body(ic_query_t *q, const unsigned char *body, size_t len);

int ic_reuse_connection(ic_query_t *q);
void ic_disconnect(ic_query_t *q);
void ic_query_deinit(ic_query_t *q);

const char *ic_strerror(int err);
const char *ic_get_icap_header(ic_query_t *q);
const char *ic_get_content(ic_query_t *q, size_t *len);

#ifdef _cplusplus
}
#endif

#endif
