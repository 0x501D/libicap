#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libicap.h>

int main()
{
    int err, rc = 0;
    ic_query_t q;

    memset(&q, 0x0, sizeof(q));

    if ((err = ic_query_init(&q)) < 0) {
        printf("%s\n", ic_strerror(err));
        exit(1);
    }

    if ((err = ic_connect("10.20.0.2", 1344, &q)) < 0) {
        printf("%s\n", ic_strerror(err));
        rc = 1;
        goto out0;
    }

    if ((err = ic_set_service(&q, "echo")) < 0) {
        printf("%s\n", ic_strerror(err));
        rc = 1;
        goto out1;
    }

    ic_get_options(&q);
out1:
    ic_disconnect(&q);
out0:
    ic_query_deinit(&q);

    return rc;
}
