#include "tls_client.h"

#include <errno.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "framing.h"

SSL_CTX *mdm_tls_client_ctx_new(const char *ca_cert_path, const char *client_cert_path,
                                 const char *client_key_path) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        fprintf(stderr, "tls_client: SSL_CTX_new failed\n");
        return NULL;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_load_verify_locations(ctx, ca_cert_path, NULL) != 1) {
        fprintf(stderr, "tls_client: failed to load CA cert '%s'\n", ca_cert_path);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_certificate_file(ctx, client_cert_path, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "tls_client: failed to load client cert '%s'\n", client_cert_path);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, client_key_path, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "tls_client: failed to load client key '%s'\n", client_key_path);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "tls_client: client certificate/key mismatch\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Require the server to present a certificate that verifies against
     * our CA. SSL_VERIFY_PEER on a client fails the handshake if the
     * server's chain doesn't verify; we additionally re-check the result
     * explicitly after connecting rather than trusting that alone. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    return ctx;
}

int mdm_conn_connect(mdm_conn_t *conn, SSL_CTX *ctx, const char *host, uint16_t port) {
    memset(conn, 0, sizeof(*conn));
    conn->fd = -1;

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "tls_client: getaddrinfo(%s:%u): %s\n", host, port, gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        fprintf(stderr, "tls_client: could not connect to %s:%u: %s\n", host, port, strerror(errno));
        return -1;
    }

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "tls_client: SSL_new failed\n");
        close(fd);
        return -1;
    }
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);

    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "tls_client: TLS handshake with %s:%u failed\n", host, port);
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(fd);
        return -1;
    }

    /* The handshake succeeding does not by itself mean the server's
     * certificate chain validated — check explicitly and fail closed. */
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        fprintf(stderr, "tls_client: server certificate verification failed: %s\n",
                X509_verify_cert_error_string(verify_result));
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);
        return -1;
    }

    X509 *peer = SSL_get_peer_certificate(ssl);
    if (peer == NULL) {
        fprintf(stderr, "tls_client: server presented no certificate\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);
        return -1;
    }
    X509_free(peer);

    conn->ctx = ctx;
    conn->ssl = ssl;
    conn->fd = fd;
    return 0;
}

int mdm_conn_send_msg(mdm_conn_t *conn, const char *json, size_t len) {
    if (mdm_frame_send_tls(conn->ssl, json, len) != 0) {
        fprintf(stderr, "tls_client: send failed\n");
        return -1;
    }
    return 0;
}

char *mdm_conn_recv_msg(mdm_conn_t *conn) {
    char *msg = mdm_frame_recv_tls(conn->ssl);
    if (msg == NULL) {
        fprintf(stderr, "tls_client: recv failed or connection closed\n");
    }
    return msg;
}

void mdm_conn_close(mdm_conn_t *conn) {
    if (conn->ssl != NULL) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
}
