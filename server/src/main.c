#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "commands_queue.h"
#include "crypto_sign.h"
#include "listener.h"
#include "messages.h"
#include "registry.h"
#include "version.h"

static void print_usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s [--version]\n"
        "       %s [--port PORT] [--db PATH] [--ca-cert PATH] [--server-cert PATH]\n"
        "                   [--server-key PATH]\n"
        "       %s --print-inventory FINGERPRINT [--db PATH]\n"
        "       %s --list-devices [--db PATH]\n"
        "       %s --queue-command FINGERPRINT --command-type NAME [--ttl SECONDS]\n"
        "                   [--signing-key PATH] [--db PATH]\n"
        "  command types: lock, reboot, wipe, usb_lockdown, firewall, file_integrity\n",
        argv0, argv0, argv0, argv0, argv0);
}

static int print_inventory(mdm_registry_t *reg, const char *fingerprint) {
    char *inv_json = NULL;
    int rc = mdm_registry_get_latest_inventory(reg, fingerprint, &inv_json);
    if (rc != 0) {
        fprintf(stderr, "no inventory snapshot found for fingerprint='%s'\n", fingerprint);
        return 1;
    }

    cJSON *parsed = cJSON_Parse(inv_json);
    free(inv_json);
    if (parsed == NULL) {
        fprintf(stderr, "stored inventory for '%s' is not valid JSON\n", fingerprint);
        return 1;
    }

    char *pretty = cJSON_Print(parsed);
    cJSON_Delete(parsed);
    if (pretty == NULL) return 1;

    printf("%s\n", pretty);
    free(pretty);
    return 0;
}

static int parse_command_type(const char *name) {
    if (strcmp(name, "lock") == 0) return MDM_CMD_LOCK;
    if (strcmp(name, "reboot") == 0) return MDM_CMD_REBOOT;
    if (strcmp(name, "wipe") == 0) return MDM_CMD_WIPE;
    if (strcmp(name, "usb_lockdown") == 0) return MDM_CMD_POLICY_USB_LOCKDOWN;
    if (strcmp(name, "firewall") == 0) return MDM_CMD_POLICY_FIREWALL;
    if (strcmp(name, "file_integrity") == 0) return MDM_CMD_POLICY_FILE_INTEGRITY;
    return MDM_CMD_UNKNOWN;
}

static int queue_command(mdm_registry_t *reg, const char *fingerprint, const char *command_type_name,
                          int ttl_seconds, const char *signing_key_path) {
    int command_type = parse_command_type(command_type_name);
    if (command_type == MDM_CMD_UNKNOWN) {
        fprintf(stderr, "unknown command type '%s'\n", command_type_name);
        return 1;
    }

    int64_t device_row_id = -1;
    int rc = mdm_registry_find_by_fingerprint(reg, fingerprint, &device_row_id);
    if (rc != 0) {
        fprintf(stderr, "no device found with fingerprint='%s' (see --list-devices)\n", fingerprint);
        return 1;
    }

    mdm_signer_t signer;
    if (mdm_signer_load(&signer, signing_key_path) != 0) {
        fprintf(stderr, "failed to load signing key '%s' (see scripts/make-signing-key.sh)\n",
                signing_key_path);
        return 1;
    }

    int queue_rc = mdm_commands_queue(reg, &signer, device_row_id, command_type, NULL, ttl_seconds,
                                       (int64_t)time(NULL));
    mdm_signer_free(&signer);

    if (queue_rc != 0) {
        fprintf(stderr, "failed to queue command\n");
        return 1;
    }

    printf("queued '%s' for device_id=%lld (fingerprint=%.16s), expires in %ds\n",
           command_type_name, (long long)device_row_id, fingerprint, ttl_seconds);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--version") == 0) {
        printf("mdm-server %s\n", MDM_VERSION);
        return 0;
    }

    uint16_t port = 7777;
    const char *db_path = "mdm-server.db";
    const char *ca_cert_path = "certs/ca.crt";
    const char *server_cert_path = "certs/server.crt";
    const char *server_key_path = "certs/server.key";
    const char *signing_key_path = "certs/signing_key.pem";
    const char *print_inventory_fingerprint = NULL;
    const char *queue_command_fingerprint = NULL;
    const char *queue_command_type_name = NULL;
    int queue_command_ttl = 300;
    int list_devices = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_path = argv[++i];
        } else if (strcmp(argv[i], "--ca-cert") == 0 && i + 1 < argc) {
            ca_cert_path = argv[++i];
        } else if (strcmp(argv[i], "--server-cert") == 0 && i + 1 < argc) {
            server_cert_path = argv[++i];
        } else if (strcmp(argv[i], "--server-key") == 0 && i + 1 < argc) {
            server_key_path = argv[++i];
        } else if (strcmp(argv[i], "--signing-key") == 0 && i + 1 < argc) {
            signing_key_path = argv[++i];
        } else if (strcmp(argv[i], "--print-inventory") == 0 && i + 1 < argc) {
            print_inventory_fingerprint = argv[++i];
        } else if (strcmp(argv[i], "--list-devices") == 0) {
            list_devices = 1;
        } else if (strcmp(argv[i], "--queue-command") == 0 && i + 1 < argc) {
            queue_command_fingerprint = argv[++i];
        } else if (strcmp(argv[i], "--command-type") == 0 && i + 1 < argc) {
            queue_command_type_name = argv[++i];
        } else if (strcmp(argv[i], "--ttl") == 0 && i + 1 < argc) {
            queue_command_ttl = atoi(argv[++i]);
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
    if (print_inventory_fingerprint != NULL) {
        rc = print_inventory(&reg, print_inventory_fingerprint);
    } else if (list_devices) {
        mdm_registry_list_devices(&reg);
        rc = 0;
    } else if (queue_command_fingerprint != NULL) {
        if (queue_command_type_name == NULL) {
            fprintf(stderr, "--queue-command requires --command-type\n");
            print_usage(argv[0]);
            rc = 1;
        } else {
            rc = queue_command(&reg, queue_command_fingerprint, queue_command_type_name,
                                queue_command_ttl, signing_key_path);
        }
    } else {
        SSL_CTX *tls_ctx = mdm_tls_server_ctx_new(ca_cert_path, server_cert_path, server_key_path);
        if (tls_ctx == NULL) {
            fprintf(stderr, "mdm-server: failed to initialize TLS, exiting\n");
            mdm_registry_close(&reg);
            return 1;
        }
        rc = mdm_listener_run(port, tls_ctx, &reg);
    }

    mdm_registry_close(&reg);
    return rc == 0 ? 0 : 1;
}
