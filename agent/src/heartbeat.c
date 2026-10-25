#include "heartbeat.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "cJSON.h"
#include "messages.h"
#include "tls_client.h"

static volatile sig_atomic_t g_stop = 0;

static void handle_stop_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static char *build_heartbeat_json(const char *device_id, int64_t now) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, MDM_FIELD_PROTO_VERSION, MDM_PROTOCOL_VERSION);
    cJSON_AddNumberToObject(root, MDM_FIELD_MSG_KIND, MDM_MSG_HEARTBEAT_REQ);
    cJSON_AddStringToObject(root, MDM_FIELD_DEVICE_ID, device_id);
    cJSON_AddNumberToObject(root, MDM_FIELD_TIMESTAMP, (double)now);

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json;
}

static int do_one_heartbeat(const mdm_agent_config_t *cfg) {
    mdm_conn_t conn;
    if (mdm_conn_connect(&conn, cfg->server_host, cfg->server_port) != 0) {
        return -1;
    }

    char *req_json = build_heartbeat_json(cfg->device_id, (int64_t)time(NULL));
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
    cJSON_Delete(resp);
    return 0;
}

int mdm_heartbeat_run(const mdm_agent_config_t *cfg) {
    signal(SIGINT, handle_stop_signal);
    signal(SIGTERM, handle_stop_signal);

    printf("mdm-agent: device_id='%s' server=%s:%u interval=%ds\n",
           cfg->device_id, cfg->server_host, cfg->server_port,
           cfg->heartbeat_interval_sec);

    while (!g_stop) {
        if (do_one_heartbeat(cfg) != 0) {
            fprintf(stderr, "heartbeat: check-in failed, will retry\n");
        }

        for (int i = 0; i < cfg->heartbeat_interval_sec && !g_stop; i++) {
            sleep(1);
        }
    }

    printf("mdm-agent: shutting down\n");
    return 0;
}
