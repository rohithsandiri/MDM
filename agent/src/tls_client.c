#include "tls_client.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "framing.h"

int mdm_conn_connect(mdm_conn_t *conn, const char *host, uint16_t port) {
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "mdm_conn_connect: getaddrinfo(%s:%u): %s\n",
                host, port, gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        fprintf(stderr, "mdm_conn_connect: could not connect to %s:%u: %s\n",
                host, port, strerror(errno));
        return -1;
    }

    conn->fd = fd;
    return 0;
}

int mdm_conn_send_msg(mdm_conn_t *conn, const char *json, size_t len) {
    if (mdm_frame_send(conn->fd, json, len) != 0) {
        fprintf(stderr, "mdm_conn_send_msg: failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

char *mdm_conn_recv_msg(mdm_conn_t *conn) {
    char *msg = mdm_frame_recv(conn->fd);
    if (msg == NULL) {
        fprintf(stderr, "mdm_conn_recv_msg: failed or connection closed\n");
    }
    return msg;
}

void mdm_conn_close(mdm_conn_t *conn) {
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
}
