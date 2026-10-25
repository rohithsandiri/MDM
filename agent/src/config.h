#ifndef MDM_AGENT_CONFIG_H
#define MDM_AGENT_CONFIG_H

#include <stdint.h>

typedef struct {
    char     server_host[256];
    uint16_t server_port;
    char     device_id[64];       /* self-reported; untrusted until Phase 3 enrollment */
    int      heartbeat_interval_sec;
} mdm_agent_config_t;

/* Fills `cfg` with defaults, then applies argv overrides. Returns 0 on
 * success, -1 on bad arguments (usage already printed to stderr). */
int mdm_config_parse_args(mdm_agent_config_t *cfg, int argc, char **argv);

#endif /* MDM_AGENT_CONFIG_H */
