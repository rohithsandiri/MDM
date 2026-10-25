#ifndef MDM_SERVER_LISTENER_H
#define MDM_SERVER_LISTENER_H

#include <openssl/ssl.h>
#include <stdint.h>

#include "registry.h"

/* Builds a server SSL_CTX that requires and verifies a client certificate
 * against `ca_cert_path` on every connection (SSL_VERIFY_PEER |
 * SSL_VERIFY_FAIL_IF_NO_PEER_CERT) — an unauthenticated or self-signed
 * client is rejected at the handshake, not waved through. Returns a
 * context, or NULL on error (logged). */
SSL_CTX *mdm_tls_server_ctx_new(const char *ca_cert_path, const char *server_cert_path,
                                 const char *server_key_path);

/* Runs a single-threaded, blocking accept loop on `port`, handling one
 * mTLS connection at a time, until interrupted (SIGINT/SIGTERM). Returns
 * 0 on clean shutdown, -1 on an unrecoverable setup error. */
int mdm_listener_run(uint16_t port, SSL_CTX *tls_ctx, mdm_registry_t *reg);

#endif /* MDM_SERVER_LISTENER_H */
