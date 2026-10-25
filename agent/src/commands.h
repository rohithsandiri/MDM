#ifndef MDM_AGENT_COMMANDS_H
#define MDM_AGENT_COMMANDS_H

#include "crypto_verify.h"

/* Verifies and dispatches one signed command envelope (as received raw
 * from a heartbeat ack's "pending_command" field — never a re-serialized
 * form of it). Enforces, in order: signature verification over the exact
 * payload bytes; a strictly-increasing sequence number persisted at
 * `state_file_path` (the actual replay defense); and an issued_at/
 * expires_at freshness window. Any failure is logged and the command is
 * dropped, never partially acted on. A command that clears all three
 * checks is forwarded, as the original raw bytes, to the privileged
 * helper over `helper_fd` — which independently re-verifies the same
 * signature itself before acting (see priv_helper.c). */
void mdm_commands_handle_envelope(const char *envelope_json, mdm_verifier_t *verifier,
                                   int helper_fd, const char *state_file_path);

#endif /* MDM_AGENT_COMMANDS_H */
