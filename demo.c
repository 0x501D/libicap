#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <libicap.h>

void usage();

int main(int argc, char **argv)
{
    int err, rc = 0;
    int opt;
    uint16_t port = 0;
    const char *optstr = "s:p:n:f:h";
    const char *icap_hdr;
    char *server = NULL;
    char *service = NULL;
    ic_query_t q;

    static const struct option longopts[] = {
        { "server", required_argument, NULL, 's' },
        { "port",   required_argument, NULL, 'p' },
        { "name",   required_argument, NULL, 'n' },
        { "file",   required_argument, NULL, 'f' },
        { "help",   no_argument,       NULL, 'h' },
        { NULL,     0,                 NULL,  0  }
    };

    while ((opt = getopt_long(argc, argv, optstr, longopts, NULL)) != -1) {
        switch (opt) {
        case 's':
            server = strdup(optarg);
            if (!server) {
                fprintf(stderr, "Out of memory\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        default:
            usage();
            exit(EXIT_FAILURE);
        }
    }

    if (!server) {
        fprintf(stderr, "Server name|IP addr is not set\n");
        usage();
        exit(EXIT_FAILURE);
    }

    if (!port) {
        port = 1344;
    }

    memset(&q, 0x0, sizeof(q));

    if ((err = ic_query_init(&q)) < 0) {
        printf("%s\n", ic_strerror(err));
        exit(1);
    }

    if ((err = ic_connect(&q, server, port)) < 0) {
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
    free(server);

    return rc;
}

void usage()
{
    printf("-s, --server <name|ipaddr> ICAP service domain name or IP address\n");
    printf("-p, --port   <number>      ICAP service port (default:1344)\n");
    printf("-n, --name   <name>        ICAP service name\n");
    printf("-f, --file   <path>        send file to ICAP service\n");
    printf("-h, --help                 print this help\n");
}
