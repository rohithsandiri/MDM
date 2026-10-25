#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "listener.h"
#include "registry.h"
#include "version.h"

static void print_usage(const char *argv0) {
    fprintf(stderr, "usage: %s [--version] [--port PORT] [--db PATH]\n", argv0);
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--version") == 0) {
        printf("mdm-server %s\n", MDM_VERSION);
        return 0;
    }

    uint16_t port = 7777;
    const char *db_path = "mdm-server.db";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_path = argv[++i];
        } else {
            fprintf(stderr, "unrecognized argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    mdm_registry_t reg;
    if (mdm_registry_open(&reg, db_path) != 0) {
        return 1;
    }

    int rc = mdm_listener_run(port, &reg);
    mdm_registry_close(&reg);

    return rc == 0 ? 0 : 1;
}
