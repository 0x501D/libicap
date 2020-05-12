#ifndef IC_CORE_H_
#define IC_CORE_H_

#define IC_EXPORT __attribute__((visibility ("default")))
#define IC_ICAP_ID "ICAP/1.0"
#define IC_CODE_OK          200
#define IC_CODE_BAD_REQUEST 400
#define IC_METHOD_REQMOD  "REQMOD"
#define IC_METHOD_RESPMOD "RESPMOD"
#define IC_METHOD_OPTIONS "OPTIONS"
#define IC_CHUNK_TERM "0\r\n\r\n"
#define IC_RN_TWICE "\r\n\r\n"
#define IC_SRV_ALLOC_SIZE 2048

#define IC_FREE(p) { free(p); p = NULL; }

#endif
