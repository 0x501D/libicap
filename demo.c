#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libicap.h>

int main(int argc, char **argv)
{
    int err, rc = 0;
    const char *icap_hdr;
    ic_query_t q;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ipaddr> <port>\n", argv[0]);
        exit(1);
    }

    memset(&q, 0x0, sizeof(q));

    if ((err = ic_query_init(&q)) < 0) {
        printf("%s\n", ic_strerror(err));
        exit(1);
    }

    if ((err = ic_connect(&q, argv[1], atoi(argv[2]))) < 0) {
        printf("%s\n", ic_strerror(err));
        rc = 1;
        goto out0;
    }

    if ((err = ic_set_service(&q, "echo")) < 0) {
        printf("%s\n", ic_strerror(err));
        rc = 1;
        goto out1;
    }

    if ((err = ic_get_options(&q)) < 0) {
        printf("%s\n", ic_strerror(err));
    }

    icap_hdr = ic_get_icap_header(&q);
    if (icap_hdr) {
        printf("%s\n", icap_hdr);
    }

out1:
    ic_disconnect(&q);
out0:
    ic_query_deinit(&q);

    return rc;
}
