/* Mutual-TLS transport. The agent authenticates the server (via the CA)
 * and authenticates itself to the server (via its enrolled client cert) —
 * a connection that merely encrypts without both checks succeeding is
 * treated as a failure, not a degraded success. */
#ifndef MDM_AGENT_TLS_CLIENT_H
#define MDM_AGENT_TLS_CLIENT_H

#include <openssl/ssl.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    SSL_CTX *ctx; /* not owned — caller builds/frees this once, reused across connects */
    SSL     *ssl;
    int      fd;
} mdm_conn_t;

/* Builds a reusable client SSL_CTX that trusts `ca_cert_path` and
 * presents the client certificate/key at `client_cert_path`/
 * `client_key_path`. Returns a context, or NULL on error (logged). */
SSL_CTX *mdm_tls_client_ctx_new(const char *ca_cert_path, const char *client_cert_path,
                                 const char *client_key_path);

/* Connects to host:port and completes a mutual-TLS handshake using `ctx`.
 * Explicitly checks SSL_get_verify_result() == X509_V_OK after the
 * handshake — a successful SSL_connect() alone does not mean the peer's
 * certificate chain was validated. Returns 0 on success, -1 on any
 * failure (logged), including a server that presents no certificate or
 * one that fails chain verification. */
int mdm_conn_connect(mdm_conn_t *conn, SSL_CTX *ctx, const char *host, uint16_t port);

int mdm_conn_send_msg(mdm_conn_t *conn, const char *json, size_t len);
char *mdm_conn_recv_msg(mdm_conn_t *conn);
void mdm_conn_close(mdm_conn_t *conn);

#endif /* MDM_AGENT_TLS_CLIENT_H */
