#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>

#include "ic_err.h"
#include "ic_utils.h"

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

void ic_str_free(ic_str_t *str)
{
    if (!str) {
        return;
    }

    if (str->data != NULL)
        free(str->data);

    str->data = NULL;
    str->alloc_bytes = 0;
    str->len = 0;
}
