#include "heartbeat.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "cJSON.h"
#include "commands.h"
#include "framing.h"
#include "inventory.h"
#include "messages.h"
#include "tls_client.h"

static volatile sig_atomic_t g_stop = 0;

static void handle_stop_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static cJSON *build_heartbeat_payload(const char *device_id, int64_t now, cJSON *inventory_json) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, MDM_FIELD_PROTO_VERSION, MDM_PROTOCOL_VERSION);
    cJSON_AddNumberToObject(root, MDM_FIELD_MSG_KIND, MDM_MSG_HEARTBEAT_REQ);
    cJSON_AddStringToObject(root, MDM_FIELD_DEVICE_ID, device_id);
    cJSON_AddNumberToObject(root, MDM_FIELD_TIMESTAMP, (double)now);
    if (inventory_json != NULL) {
        cJSON_AddItemToObject(root, MDM_FIELD_INVENTORY, inventory_json);
    }
    return root;
}

/* Asks the privileged helper what its background USB/file-integrity
 * detection threads have queued since the last ask. This is a local-only
 * request (never signed — it isn't an action, just reading the helper's
 * own telemetry back out) so it uses the plain poll_events shape the
 * helper special-cases, not a signed envelope. Returns a new cJSON array
 * (caller owns it), empty on any failure — a lost event is acceptable
 * telemetry loss, never a reason to fail the heartbeat. */
static cJSON *poll_helper_events(int helper_fd) {
    cJSON *empty = cJSON_CreateArray();
    if (helper_fd < 0) return empty;

    static const char *POLL_REQUEST = "{\"poll_events\":true}";
    if (mdm_frame_send(helper_fd, POLL_REQUEST, strlen(POLL_REQUEST)) != 0) {
        fprintf(stderr, "heartbeat: failed to poll helper for policy events\n");
        return empty;
    }

    char *resp_json = mdm_frame_recv(helper_fd);
    if (resp_json == NULL) {
        fprintf(stderr, "heartbeat: no response polling helper for policy events\n");
        return empty;
    }

    cJSON *resp = cJSON_Parse(resp_json);
    free(resp_json);
    if (resp == NULL) return empty;

    cJSON *events = cJSON_DetachItemFromObjectCaseSensitive(resp, MDM_FIELD_POLICY_EVENTS);
    cJSON_Delete(resp);
    if (events == NULL) return empty;

    cJSON_Delete(empty);
    return events;
}

/* Builds the heartbeat+inventory payload and, if it would exceed the wire
 * framing's max frame size (package lists are the usual culprit on a real
 * machine), progressively sheds the heaviest fields rather than sending a
 * frame the server would reject outright. */
static char *build_bounded_request_json(const char *device_id, int64_t now, int helper_fd) {
    mdm_inventory_t inv;
    mdm_inventory_collect(&inv);
    cJSON *inv_json = mdm_inventory_to_json(&inv);
    mdm_inventory_free(&inv);

    cJSON *root = build_heartbeat_payload(device_id, now, inv_json);

    cJSON *events = poll_helper_events(helper_fd);
    if (cJSON_GetArraySize(events) > 0) {
        cJSON_AddItemToObject(root, MDM_FIELD_POLICY_EVENTS, events);
    } else {
        cJSON_Delete(events);
    }

    char *json = cJSON_PrintUnformatted(root);

    if (json != NULL && strlen(json) + 1 > MDM_FRAME_MAX_LEN) {
        fprintf(stderr, "heartbeat: payload too large (%zu bytes), dropping package list\n",
                strlen(json));
        cJSON_DeleteItemFromObject(inv_json, "packages");
        cJSON_AddItemToObject(inv_json, "packages_truncated", cJSON_CreateTrue());
        free(json);
        json = cJSON_PrintUnformatted(root);
    }

    if (json != NULL && strlen(json) + 1 > MDM_FRAME_MAX_LEN) {
        fprintf(stderr, "heartbeat: payload still too large after truncation, dropping inventory\n");
        cJSON_DeleteItemFromObject(root, MDM_FIELD_INVENTORY);
        free(json);
        json = cJSON_PrintUnformatted(root);
    }

    cJSON_Delete(root);
    return json;
}

static int do_one_heartbeat(const mdm_agent_config_t *cfg, SSL_CTX *tls_ctx,
                             mdm_verifier_t *verifier, int helper_fd) {
    mdm_conn_t conn;
    if (mdm_conn_connect(&conn, tls_ctx, cfg->server_host, cfg->server_port) != 0) {
        return -1;
    }

    char *req_json = build_bounded_request_json(cfg->device_id, (int64_t)time(NULL), helper_fd);
    if (req_json == NULL) {
        fprintf(stderr, "heartbeat: failed to build request JSON\n");
        mdm_conn_close(&conn);
        return -1;
    }

    int rc = mdm_conn_send_msg(&conn, req_json, strlen(req_json));
    free(req_json);
    if (rc != 0) {
        mdm_conn_close(&conn);
        return -1;
    }

    char *resp_json = mdm_conn_recv_msg(&conn);
    mdm_conn_close(&conn);
    if (resp_json == NULL) {
        return -1;
    }

    cJSON *resp = cJSON_Parse(resp_json);
    free(resp_json);
    if (resp == NULL) {
        fprintf(stderr, "heartbeat: malformed ack JSON from server\n");
        return -1;
    }

    cJSON *kind = cJSON_GetObjectItemCaseSensitive(resp, MDM_FIELD_MSG_KIND);
    if (!cJSON_IsNumber(kind) || (int)kind->valuedouble != MDM_MSG_HEARTBEAT_ACK) {
        fprintf(stderr, "heartbeat: unexpected ack msg_kind\n");
        cJSON_Delete(resp);
        return -1;
    }

    printf("heartbeat: ack received for device '%s'\n", cfg->device_id);

    cJSON *pending_command = cJSON_GetObjectItemCaseSensitive(resp, MDM_FIELD_PENDING_COMMAND);
    if (cJSON_IsObject(pending_command)) {
        char *envelope_json = cJSON_PrintUnformatted(pending_command);
        if (envelope_json != NULL) {
            mdm_commands_handle_envelope(envelope_json, verifier, helper_fd, cfg->state_file_path);
            free(envelope_json);
        }
    }

    cJSON_Delete(resp);
    return 0;
}

int mdm_heartbeat_run(const mdm_agent_config_t *cfg, SSL_CTX *tls_ctx, mdm_verifier_t *verifier,
                      int helper_fd) {
    signal(SIGINT, handle_stop_signal);
    signal(SIGTERM, handle_stop_signal);

    printf("mdm-agent: device_id='%s' server=%s:%u interval=%ds (mTLS)\n",
           cfg->device_id, cfg->server_host, cfg->server_port,
           cfg->heartbeat_interval_sec);

    while (!g_stop) {
        if (do_one_heartbeat(cfg, tls_ctx, verifier, helper_fd) != 0) {
            fprintf(stderr, "heartbeat: check-in failed, will retry\n");
        }

        for (int i = 0; i < cfg->heartbeat_interval_sec && !g_stop; i++) {
            sleep(1);
        }
    }

    printf("mdm-agent: shutting down\n");
    return 0;
}
