#include <stdio.h>
#include <string.h>

#include "config.h"
#include "heartbeat.h"
#include "version.h"

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--version") == 0) {
        printf("mdm-agent %s\n", MDM_VERSION);
        return 0;
    }

    mdm_agent_config_t cfg;
    if (mdm_config_parse_args(&cfg, argc, argv) != 0) {
        return 1;
    }

    return mdm_heartbeat_run(&cfg) == 0 ? 0 : 1;
}
