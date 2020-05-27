#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

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
    char *path = NULL;
    ic_query_t q;

    memset(&q, 0x0, sizeof(q));

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
        case 'n':
            service = strdup(optarg);
            if (!service) {
                fprintf(stderr, "Out of memory\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'f':
            path = strdup(optarg);
            if (!path) {
                fprintf(stderr, "Out of memory\n");
                exit(EXIT_FAILURE);
            }
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

    if (path) {
        struct stat info;
        int fd, hdr_len;

        if (!service) {
            fprintf(stderr, "ICAP service is not set\n");
            goto out;
        }
#if 0
        ctx.service = service;
        if (ic_set_service(&q, service) != 0) {
            fprintf(stderr, "Cannot set service\n");
            goto out;
        }

        memset(&info, 0, sizeof(info));

        if (stat(path, &info) == -1) {
            fprintf(stderr, "Cannot open '%s': %s\n", path, strerror(errno));
            goto out;
        }

        ctx.body_len = info.st_size;
        if ((ctx.body = malloc(ctx.body_len)) == NULL) {
            fprintf(stderr, "Out of memory\n");
            goto out;
        }

        if ((fd = open(path, O_RDONLY)) == -1) {
            fprintf(stderr, "Cannot open '%s': %s\n", path, strerror(errno));
            goto out;
        }

        if (read(fd, ctx.body, ctx.body_len) == -1) {
            fprintf(stderr, "Cannot read '%s': %s\n", path, strerror(errno));
            goto out;
        }

        if ((hdr_len = asprintf(&ctx.hdr, "HTTP/1.1 200 OK\r\n\r\n")) == -1) {
            fprintf(stderr, "Out of memory\n");
            goto out;
        }
            printf("%d\n", hdr_len);

        ctx.hdr_len = hdr_len;

        if (ic_send_respmod(&q, &ctx) != 0) {
            //...
        }
#endif
        close(fd);
    }

    if (!port) {
        port = 1344;
    }

    if ((err = ic_query_init(&q)) < 0) {
        printf("%s\n", ic_strerror(err));
        exit(1);
    }

    if ((err = ic_connect(&q, server, port)) < 0) {
        printf("%s\n", ic_strerror(err));
        rc = 1;
        goto out;
    }

    if ((err = ic_get_options(&q, "echo")) < 0) {
        printf("%s\n", ic_strerror(err));
    }

    icap_hdr = ic_get_icap_header(&q);
    if (icap_hdr) {
        printf("%s\n", icap_hdr);
    }

    if (path) {
        //...
    }

    ic_disconnect(&q);
out:
    ic_query_deinit(&q);
    free(server);
    free(service);
    free(path);

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
