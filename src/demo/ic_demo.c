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
    int err, rc = 0, fd = -1;
    int opt, allow_204 = 0;
    uint16_t port = 0;
    const char *optstr = "as:p:n:f:h";
    const char *icap_hdr;
    unsigned char *body = NULL;
    unsigned char *resp_hdr = NULL;
    ic_ctx_type_t resp_type = 0;
    char *server = NULL;
    char *service = NULL;
    char *path = NULL;
    ic_query_t q;

    memset(&q, 0x0, sizeof(q));

    static const struct option longopts[] = {
        { "server",    required_argument, NULL, 's' },
        { "port",      required_argument, NULL, 'p' },
        { "name",      required_argument, NULL, 'n' },
        { "file",      required_argument, NULL, 'f' },
        { "allow-204", no_argument,       NULL, 'a' },
        { "help",      no_argument,       NULL, 'h' },
        { NULL,        0,                 NULL,  0  }
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
        case 'a':
            allow_204 = 1;
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

    if ((err = ic_query_init(&q)) < 0) {
        printf("%s\n", ic_strerror(err));
        exit(1);
    }

    if (allow_204) {
        ic_allow_204(&q);
    }

    if (!port) {
        port = 1344;
    }

    if ((err = ic_connect(&q, server, port)) < 0) {
        printf("%s\n", ic_strerror(err));
        rc = 1;
        goto out;
    }

    if ((err = ic_get_options(&q, "echo")) < 0) {
        printf("%s\n", ic_strerror(err));
    }

    icap_hdr = ic_get_icap_hdr(&q);
    if (icap_hdr) {
        printf("ICAP response:\n\n%s\n\n", icap_hdr);
    }

    if (path) {
        struct stat info;
        int hdr_len;
        size_t body_len;

        ic_reuse_connection(&q, 0);

        if (!service) {
            fprintf(stderr, "ICAP service is not set\n");
            goto out;
        }

        if (ic_set_service(&q, service) != 0) {
            fprintf(stderr, "Cannot set service\n");
            goto out;
        }

        memset(&info, 0, sizeof(info));

        if (stat(path, &info) == -1) {
            fprintf(stderr, "Cannot open '%s': %s\n", path, strerror(errno));
            goto out;
        }

        body_len = info.st_size;
        if ((body = malloc(body_len)) == NULL) {
            fprintf(stderr, "Out of memory\n");
            goto out;
        }

        if ((fd = open(path, O_RDONLY)) == -1) {
            fprintf(stderr, "Cannot open '%s': %s\n", path, strerror(errno));
            goto out;
        }

        if (read(fd, body, body_len) == -1) {
            fprintf(stderr, "Cannot read '%s': %s\n", path, strerror(errno));
            goto out;
        }
#if 1
        if ((hdr_len = asprintf((char **) &resp_hdr, "HTTP/1.1 200 OK\r\n"
                        "Content-Length: %zu\r\n\r\n", body_len)) == -1) {
            fprintf(stderr, "Out of memory\n");
            goto out;
        }
#endif
#if 0
        if ((hdr_len = asprintf((char **) &resp_hdr, "HTTP/1.1 200 OK\r\n"
                        "Content-Length: 68\r\n\r\n")) == -1) {
            fprintf(stderr, "Out of memory\n");
            goto out;
        }
#endif

        if ((err = ic_set_res_hdr(&q, resp_hdr, hdr_len, &resp_type)) != 0) {
            printf("%s\n", ic_strerror(err));
            goto out;
        }

        if ((err = ic_set_body(&q, body, body_len)) == -1) {
            printf("%s\n", ic_strerror(err));
            goto out;
        }

        rc = ic_send_respmod(&q);
        if (rc == 1) {
#if 0
            const unsigned char *body_2 = "STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            ic_reuse_connection(&q, 1);

            if ((err = ic_set_body(&q, body_2, 34)) == -1) {
                printf("%s\n", ic_strerror(err));
                goto out;
            }

            ic_send_respmod(&q);
#endif
        } else if (rc == 0) {
            size_t ctx_len;
            const char *ctx = ic_get_content(&q, &ctx_len, &err);

            if (ctx) {
                unlink("/tmp/content");
                int fd = open("/tmp/content", O_CREAT|O_WRONLY, 0660);
                write(fd, ctx, ctx_len);
                close(fd);
            } else {
                printf("%s\n", ic_strerror(err));
            }

        }

        icap_hdr = ic_get_icap_hdr(&q);
        if (icap_hdr) {
            printf("ICAP response:\n\n%s\n\n", icap_hdr);
        }

        printf("ICAP status code:%d\n", ic_get_status_code(&q));

        close(fd);
        fd = -1;
    }

    ic_disconnect(&q);
out:
    if (fd != -1) {
        close(fd);
    }
    ic_query_deinit(&q);
    free(server);
    free(service);
    free(path);
    free(body);
    free(resp_hdr);

    return rc;
}

void usage()
{
    printf("-s, --server <name|ipaddr> ICAP service domain name or IP address\n");
    printf("-p, --port   <number>      ICAP service port (default:1344)\n");
    printf("-n, --name   <name>        ICAP service name\n");
    printf("-f, --file   <path>        send file to ICAP service\n");
    printf("-a, --allow-204            include Allow: 204\n");
    printf("-h, --help                 print this help\n");
}
