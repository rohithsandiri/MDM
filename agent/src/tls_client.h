/* Plain-TCP transport for Phase 1/2. Phase 3 swaps the implementation
 * behind this same interface for mutual TLS (OpenSSL) without touching
 * heartbeat.c or any other caller. */
#ifndef MDM_AGENT_TLS_CLIENT_H
#define MDM_AGENT_TLS_CLIENT_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    int fd;
} mdm_conn_t;

/* Connects to host:port. Returns 0 on success, -1 on failure (logged). */
int mdm_conn_connect(mdm_conn_t *conn, const char *host, uint16_t port);

/* Sends one length-prefixed JSON frame. Returns 0 on success, -1 on error. */
int mdm_conn_send_msg(mdm_conn_t *conn, const char *json, size_t len);

/* Reads one length-prefixed JSON frame. Returns a malloc'd, NUL-terminated
 * string (caller frees) on success, or NULL on error/EOF. */
char *mdm_conn_recv_msg(mdm_conn_t *conn);

void mdm_conn_close(mdm_conn_t *conn);

#endif /* MDM_AGENT_TLS_CLIENT_H */
