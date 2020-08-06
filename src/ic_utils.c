#include "ic_core.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>

#include "ic_err.h"
#include "ic_utils.h"

static int ic_str_alloc_mem(ic_str_t *str, const char *src, size_t len);
static int ic_str_append_mem(ic_str_t *str, const char *src, size_t len);

int ic_strtoui(const char *s, uint32_t *res, int base)
{
    uint64_t r;
    char *endp;

    if (!s || !res) {
        return -IC_ERR_NULL_POINTER_INT;
    }

    r = strtoul(s, &endp, base);

    if ((r == ULONG_MAX && errno == ERANGE) || (r > UINT32_MAX)) {
        return -IC_ERR_INT_OVERFLOW;
    }

    if ((endp == s) || (*endp != '\0')) {
        return -IC_ERR_BAD_INT;
    }

    *res = r;

    return 0;
}

int ic_strtoul(const char *s, uint64_t *res, int base)
{
    uint64_t r;
    char *endp;

    if (!s || !res) {
        return -IC_ERR_NULL_POINTER_INT;
    }

    r = strtoul(s, &endp, base);

    if (r == ULLONG_MAX && errno == ERANGE) {
        return -IC_ERR_INT_OVERFLOW;
    }

    if ((endp == s) || (*endp != '\0')) {
        return -IC_ERR_BAD_INT;
    }

    *res = r;

    return 0;
}

int ic_str_format(ic_str_t *str, const char *fmt, ...)
{
    int rc;
    int len = 0;
    char *buf = NULL;
    va_list args;

    /* get required length */
    va_start(args, fmt);
    len = vsnprintf(buf, 0, fmt, args);
    va_end(args);

    if (len < 0) {
        return -IC_ERR_INVAL_LEN_INT;
    }

    len++; /* for \0 */

    if ((buf = calloc(1, len)) == NULL) {
        return -IC_ERR_ENOMEM;
    }

    va_start(args, fmt);
    len = vsnprintf(buf, len, fmt, args);
    if (len < 0) {
        return -IC_ERR_INVAL_LEN_INT;
    }
    va_end(args);

    rc = ic_str_alloc_mem(str, buf, len);
    free(buf);

    return rc;
}

int ic_str_format_cat(ic_str_t *str, const char *fmt, ...)
{
    int len = 0, rc = 0;
    char *buf = NULL;
    va_list args;

    /* get required length */
    va_start(args, fmt);
    len = vsnprintf(buf, 0, fmt, args);
    va_end(args);

    if (len < 0) {
        return -IC_ERR_INVAL_LEN_INT;
    }

    len++; /* for \0 */

    if ((buf = calloc(1, len)) == NULL) {
        return -IC_ERR_ENOMEM;
    }

    va_start(args, fmt);
    len = vsnprintf(buf, len, fmt, args);
    if (len < 0) {
        return -IC_ERR_INVAL_LEN_INT;
    }
    va_end(args);

    rc = ic_str_append_mem(str, buf, len);
    free(buf);

    return rc;
}

static int ic_str_alloc_mem(ic_str_t *str, const char *src, size_t len)
{
    if (!str)
        return -IC_ERR_NULL_POINTER_INT;

    size_t len_needed;

    if (len + 1 < len) {
        return -IC_ERR_INT_OVERFLOW_INT;
    }

    len_needed = len + 1;

    if (len_needed > str->alloc_bytes) {
        free(str->data);
        str->data = malloc(len_needed);
        if (!str->data) {
            return -IC_ERR_ENOMEM;
        }
        str->alloc_bytes = len_needed;
    }

    if (src) {
        memcpy(str->data, src, len);
        str->data[len] = '\0';
    }

    str->len = len;
    return 0;
}

static int ic_str_append_mem(ic_str_t *str, const char *src, size_t len)
{
    size_t len_needed;

    if (len + str->len < len) {
        return -IC_ERR_INT_OVERFLOW_INT;
    }

    len_needed = len + str->len;
    if (len_needed + 1 < len_needed) {
        return -IC_ERR_INT_OVERFLOW_INT;
    }

    len_needed++;

    if (len_needed > str->alloc_bytes) {
        char *tmpp = realloc(str->data, len_needed);
        if (!tmpp) {
            free(str->data);
            return -IC_ERR_ENOMEM;
        }
        str->data = tmpp;
        str->alloc_bytes = len_needed;
    }

    memcpy(str->data + str->len, src, len);
    str->data[str->len + len] = '\0';
    str->len += len;

    return 0;
}

int ic_extract_substr(ic_substr_t *s)
{
    int rc = 1;
    char *res = NULL;
    char *sub_begin, *p;
    size_t res_buf_len, sub_offset, str_rest;
    char *start = NULL, *end = NULL;

    sub_begin = memmem(s->str, s->str_len, s->sub, s->sub_len);
    if (!sub_begin) {
        return rc;
    }

    sub_offset = (unsigned char *) sub_begin - (unsigned char *) s->str;
    str_rest = s->str_len - sub_offset;
    p = sub_begin;

    for (size_t n = 0; n < str_rest; n++, p++) {
        char ch = *p;

        if (ch == s->begin) {
            start = p + 1;
        }

        if (start && (ch == s->end)) {
            end = p;
            res_buf_len = end - start;

            if ((res = calloc(1, res_buf_len + 1)) == NULL) {
                return -IC_ERR_ENOMEM;
            }

            memcpy(res, start, res_buf_len);
            break;
        }
    }

    if (res) {
        s->result = res;
        rc = 0;
    }

    return rc;
}

void ic_str_free(ic_str_t *str)
{
    if (!str) {
        return;
    }

    free(str->data);

    str->data = NULL;
    str->alloc_bytes = 0;
    str->len = 0;
}

void ic_debug(const char *path, const char *fmt, ...)
{
    if (!path) {
        return;
    }

    va_list args;
    FILE *fp;

    if ((fp = fopen(path, "a+")) == NULL)
        return;

    va_start(args, fmt);
    vfprintf(fp, fmt, args);
    va_end(args);

    fclose(fp);
}
