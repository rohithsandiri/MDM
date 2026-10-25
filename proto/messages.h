/* Shared message and command contract between mdm-agent and mdm-server.
 * This is the one place command semantics are defined — the agent dispatches
 * on mdm_command_type_t only, never on a raw string, so adding a command
 * means adding a value here plus a handler, not a new code path. */
#ifndef MDM_PROTO_MESSAGES_H
#define MDM_PROTO_MESSAGES_H

#include <stdint.h>

#define MDM_PROTOCOL_VERSION      1
#define MDM_DEVICE_ID_LEN         37   /* UUID string (36) + NUL */
#define MDM_MAX_SIGNATURE_B64_LEN 1024
#define MDM_MAX_PAYLOAD_LEN       65536

/* ---- Top-level message kinds exchanged over the mTLS connection ---- */
typedef enum {
    MDM_MSG_UNKNOWN       = 0,
    MDM_MSG_HEARTBEAT_REQ = 1,  /* agent -> server */
    MDM_MSG_HEARTBEAT_ACK = 2,  /* server -> agent */
    MDM_MSG_INVENTORY_REQ = 3,  /* agent -> server, attached to a heartbeat */
    MDM_MSG_COMMAND       = 4,  /* server -> agent, signed envelope */
    MDM_MSG_COMMAND_RESULT = 5, /* agent -> server */
    MDM_MSG_COUNT
} mdm_msg_kind_t;

/* ---- Fixed, enumerated remote command set ----
 * Every command the agent can ever execute lives here. The agent's
 * dispatcher (commands.c) switches on this enum; there is no path from
 * server input to shell/eval. */
typedef enum {
    MDM_CMD_UNKNOWN                 = 0,
    MDM_CMD_LOCK                    = 1,  /* lock all sessions (logind) */
    MDM_CMD_REBOOT                  = 2,  /* reboot the host */
    MDM_CMD_WIPE                    = 3,  /* secure-wipe one target directory */
    MDM_CMD_POLICY_USB_LOCKDOWN     = 4,  /* apply/clear USB mass-storage policy */
    MDM_CMD_POLICY_FIREWALL         = 5,  /* apply an nftables ruleset */
    MDM_CMD_POLICY_FILE_INTEGRITY   = 6,  /* add/remove an inotify watch target */
    MDM_CMD_COUNT
} mdm_command_type_t;

/* ---- JSON field names (shared string constants so agent/server never drift) ---- */
#define MDM_FIELD_PROTO_VERSION   "proto_version"
#define MDM_FIELD_MSG_KIND        "msg_kind"
#define MDM_FIELD_DEVICE_ID       "device_id"
#define MDM_FIELD_TIMESTAMP       "timestamp"
#define MDM_FIELD_INVENTORY       "inventory"
#define MDM_FIELD_COMMAND_TYPE    "command_type"
#define MDM_FIELD_COMMAND_ID      "command_id"
#define MDM_FIELD_PARAMS          "params"
#define MDM_FIELD_PAYLOAD         "payload"      /* canonical bytes that get signed */
#define MDM_FIELD_SIGNATURE       "signature"    /* base64, over FIELD_PAYLOAD */
#define MDM_FIELD_SIGNER_KEY_ID   "signer_key_id"
#define MDM_FIELD_RESULT_CODE     "result_code"
#define MDM_FIELD_RESULT_MESSAGE  "result_message"

/* ---- Signed command envelope (Phase 3 onward) ----
 * `payload` is the exact JSON text that was signed; the agent must verify
 * `signature` over `payload` with the embedded server public key before
 * parsing `payload` into a command. Anything that fails verification is
 * rejected and logged, never partially acted on. */
typedef struct {
    char     signer_key_id[64];
    char     signature_b64[MDM_MAX_SIGNATURE_B64_LEN];
    char     payload[MDM_MAX_PAYLOAD_LEN]; /* raw JSON, verified before parse */
} mdm_signed_envelope_t;

/* ---- Result codes returned by the agent for an executed command ---- */
typedef enum {
    MDM_RESULT_OK                 = 0,
    MDM_RESULT_ERR_VERIFY_FAILED  = 1,
    MDM_RESULT_ERR_MALFORMED      = 2,
    MDM_RESULT_ERR_UNKNOWN_CMD    = 3,
    MDM_RESULT_ERR_EXEC_FAILED    = 4,
    MDM_RESULT_ERR_DENIED         = 5
} mdm_result_code_t;

#endif /* MDM_PROTO_MESSAGES_H */
