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
/* Inventory payloads (installed-package lists especially) run well past
 * a heartbeat's few dozen bytes on a real machine, not just the sparse
 * test container — sized generously so a normal package count never
 * trips the ceiling, while still bounding worst-case memory. */
#define MDM_MAX_PAYLOAD_LEN       (4 * 1024 * 1024)

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
#define MDM_FIELD_PENDING_COMMAND "pending_command" /* signed envelope, embedded in a heartbeat ack */

/* Replay-protection fields, inside the signed payload (so they're covered
 * by the signature, not just the envelope). `sequence` is the actual
 * enforcement mechanism: strictly increasing per device, persisted by the
 * agent, and any command at or below the last-accepted value is rejected
 * outright regardless of signature validity. `issued_at`/`expires_at` are
 * a second, independent bound (catches a captured-but-not-yet-replayed
 * command sitting unused past its window). `nonce` is carried for audit
 * logging of exactly which command instance was seen. */
#define MDM_FIELD_SEQUENCE        "sequence"
#define MDM_FIELD_NONCE           "nonce"
#define MDM_FIELD_ISSUED_AT       "issued_at"
#define MDM_FIELD_EXPIRES_AT      "expires_at"

/* Policy enforcement (Phase 4). `policy_events` is an array of
 * {policy_type, message, timestamp} objects attached to a heartbeat
 * request — the agent's privileged helper runs the USB/file-integrity
 * detection loops itself (it already holds root, and already
 * independently re-verifies the signed command that enabled them), and
 * the unprivileged main loop just polls it for queued events each
 * heartbeat rather than receiving them asynchronously. */
#define MDM_FIELD_POLICY_EVENTS   "policy_events"
#define MDM_FIELD_POLICY_TYPE     "policy_type"
#define MDM_FIELD_MESSAGE         "message"

/* Well-known keys inside a command's `params` object. Each command type
 * only looks at the subset relevant to it. */
#define MDM_PARAM_ENABLED         "enabled"  /* usb_lockdown: bool */
#define MDM_PARAM_ACTION          "action"   /* firewall/file_integrity: "apply"/"clear"/"watch"/"unwatch" */
#define MDM_PARAM_RULES           "rules"    /* firewall: array of nft rule strings */
#define MDM_PARAM_PATH            "path"     /* file_integrity: path to watch/unwatch */

/* ---- Signed command envelope (Phase 3 onward) ----
 * `payload` is the exact JSON text that was signed, carried as a JSON
 * string value so it survives the wire byte-for-byte; the agent verifies
 * `signature` (Ed25519, base64) over those exact bytes *before* parsing
 * `payload` into a command. Never re-serialize-then-verify: parse only
 * after the raw bytes have already checked out. Illustrative of the wire
 * shape only — code works with cJSON/dynamic strings, not this struct
 * directly, since a 4MB fixed buffer has no business on the stack. */
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
