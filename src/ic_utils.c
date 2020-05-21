#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

#include "ic_err.h"

int ic_strtoui(const char *s, uint32_t *res, int base)
{
    uint64_t r;
    char *endp;

    if (!s || !res) {
        return -IC_ERR_NULL_POINTER;
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

size_t ic_count_digit(size_t n)
{
    size_t res = 0;

    if (!n) {
        return 1;
    }

    while (n) {
        n /= 10;
        res++;
    }

    return res;
}
