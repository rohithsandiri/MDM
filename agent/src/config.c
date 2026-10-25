#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void print_usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s [--server HOST] [--port PORT] [--device-id ID] [--interval SECONDS]\n",
        argv0);
}

static void apply_defaults(mdm_agent_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->server_host, "127.0.0.1", sizeof(cfg->server_host) - 1);
    cfg->server_port = 7777;
    cfg->heartbeat_interval_sec = 5;

    char hostname[64];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        hostname[sizeof(hostname) - 1] = '\0';
        snprintf(cfg->device_id, sizeof(cfg->device_id), "%s", hostname);
    } else {
        snprintf(cfg->device_id, sizeof(cfg->device_id), "unknown-device");
    }
}

int mdm_config_parse_args(mdm_agent_config_t *cfg, int argc, char **argv) {
    apply_defaults(cfg);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            strncpy(cfg->server_host, argv[++i], sizeof(cfg->server_host) - 1);
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            cfg->server_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--device-id") == 0 && i + 1 < argc) {
            strncpy(cfg->device_id, argv[++i], sizeof(cfg->device_id) - 1);
        } else if (strcmp(argv[i], "--interval") == 0 && i + 1 < argc) {
            cfg->heartbeat_interval_sec = atoi(argv[++i]);
        } else {
            fprintf(stderr, "unrecognized argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return -1;
        }
    }

    if (cfg->server_port == 0 || cfg->heartbeat_interval_sec <= 0) {
        fprintf(stderr, "invalid --port or --interval value\n");
        print_usage(argv[0]);
        return -1;
    }

    return 0;
}
