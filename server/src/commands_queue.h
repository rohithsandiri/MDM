#ifndef MDM_SERVER_COMMANDS_QUEUE_H
#define MDM_SERVER_COMMANDS_QUEUE_H

#include <stdint.h>

#include "crypto_sign.h"
#include "registry.h"

/* Builds a signed command envelope for `device_row_id` and queues it for
 * delivery on that device's next heartbeat ack. The payload (command
 * type, a fresh strictly-increasing sequence number, a nonce, and an
 * issued_at/expires_at window) is signed as one exact byte sequence —
 * the agent verifies over those same bytes before ever parsing them.
 * `params_json` may be NULL for a command with no parameters. Returns 0
 * on success, -1 on error (logged). */
int mdm_commands_queue(mdm_registry_t *reg, mdm_signer_t *signer, int64_t device_row_id,
                        int command_type, const char *params_json, int ttl_seconds, int64_t now);

#endif /* MDM_SERVER_COMMANDS_QUEUE_H */
