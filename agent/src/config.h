#ifndef MDM_AGENT_CONFIG_H
#define MDM_AGENT_CONFIG_H

#include <stdint.h>

typedef struct {
    char     server_host[256];
    uint16_t server_port;
    char     device_id[64];       /* self-reported; untrusted — the mTLS client cert is authoritative */
    int      heartbeat_interval_sec;

    char     ca_cert_path[512];       /* CA that signed the server's cert */
    char     client_cert_path[512];   /* this device's enrolled client cert */
    char     client_key_path[512];    /* this device's private key (never transmitted) */
    char     signing_pubkey_path[512]; /* Ed25519 public key for verifying signed commands */

    char     state_file_path[512];  /* persists the last-accepted command sequence number */
    char     unprivileged_user[64]; /* account the main loop drops to after spawning the helper */
} mdm_agent_config_t;

/* Fills `cfg` with defaults, then applies argv overrides. Returns 0 on
 * success, -1 on bad arguments (usage already printed to stderr). */
int mdm_config_parse_args(mdm_agent_config_t *cfg, int argc, char **argv);

#endif /* MDM_AGENT_CONFIG_H */
