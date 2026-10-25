#ifndef MDM_AGENT_HEARTBEAT_H
#define MDM_AGENT_HEARTBEAT_H

#include <openssl/ssl.h>

#include "config.h"
#include "crypto_verify.h"

/* Runs the mTLS check-in loop in the foreground until interrupted
 * (SIGINT/SIGTERM). `tls_ctx` must already be configured for mutual TLS
 * (see mdm_tls_client_ctx_new). `verifier` holds the trusted
 * command-signing public key, used for this process's own (first-layer)
 * verification of any pending command in a heartbeat ack before it's
 * forwarded to the privileged helper over `helper_fd`. Returns 0 on
 * clean shutdown, -1 on an unrecoverable setup error. */
int mdm_heartbeat_run(const mdm_agent_config_t *cfg, SSL_CTX *tls_ctx, mdm_verifier_t *verifier,
                      int helper_fd);

#endif /* MDM_AGENT_HEARTBEAT_H */
