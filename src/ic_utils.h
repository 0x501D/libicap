#ifndef IC_UTILS_H_
#define IC_UTILS_H_

typedef struct ic_str {
    char *data;
    size_t len;
    size_t alloc_bytes;
} ic_str_t;

typedef struct ic_substr {
    void *str;
    void *sub;
    char *result;
    size_t str_len;
    size_t sub_len;
    char begin;
    char end;
} ic_substr_t;

int ic_extract_substr(ic_substr_t *s);
int ic_strtoui(const char *s, uint32_t *res, int base);
int ic_strtoul(const char *s, uint64_t *res, int base);
int ic_str_format_cat(ic_str_t *str, const char *fmt, ...)
    __attribute__ ((format(printf, 2, 3)));
void ic_str_free(ic_str_t *str);

#endif
