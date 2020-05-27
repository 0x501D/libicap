#ifndef LIBICAP_H_
#define LIBICAP_H_

#include <stdint.h>

#ifdef _cplusplus
extern "C" {
#endif

typedef struct ic_query {
    void *data;
} ic_query_t;

int ic_query_init(ic_query_t *q);
int ic_connect(ic_query_t *q, const char *srv, uint16_t port);
int ic_get_options(ic_query_t *q, const char *service);
int ic_send_respmod(ic_query_t *q);

int ic_set_service(ic_query_t *q, const char *service);

void ic_disconnect(ic_query_t *q);
void ic_query_deinit(ic_query_t *q);

const char *ic_strerror(int err);
const char *ic_get_icap_header(ic_query_t *q);
const char *ic_get_content(ic_query_t *q, size_t *len);

#ifdef _cplusplus
}
#endif

#endif
