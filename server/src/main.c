#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "listener.h"
#include "registry.h"
#include "version.h"

static void print_usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s [--version] [--port PORT] [--db PATH]\n"
        "       %s --print-inventory DEVICE_ID [--db PATH]\n",
        argv0, argv0);
}

static int print_inventory(mdm_registry_t *reg, const char *device_id) {
    char *inv_json = NULL;
    int rc = mdm_registry_get_latest_inventory(reg, device_id, &inv_json);
    if (rc != 0) {
        fprintf(stderr, "no inventory snapshot found for device_id='%s'\n", device_id);
        return 1;
    }

    cJSON *parsed = cJSON_Parse(inv_json);
    free(inv_json);
    if (parsed == NULL) {
        fprintf(stderr, "stored inventory for '%s' is not valid JSON\n", device_id);
        return 1;
    }

    char *pretty = cJSON_Print(parsed);
    cJSON_Delete(parsed);
    if (pretty == NULL) {
        return 1;
    }

    printf("%s\n", pretty);
    free(pretty);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--version") == 0) {
        printf("mdm-server %s\n", MDM_VERSION);
        return 0;
    }

    uint16_t port = 7777;
    const char *db_path = "mdm-server.db";
    const char *print_inventory_device_id = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_path = argv[++i];
        } else if (strcmp(argv[i], "--print-inventory") == 0 && i + 1 < argc) {
            print_inventory_device_id = argv[++i];
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

    int rc;
    if (print_inventory_device_id != NULL) {
        rc = print_inventory(&reg, print_inventory_device_id);
    } else {
        rc = mdm_listener_run(port, &reg);
    }

    mdm_registry_close(&reg);
    return rc == 0 ? 0 : 1;
}
