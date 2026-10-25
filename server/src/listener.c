#include "listener.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "cJSON.h"
#include "framing.h"
#include "messages.h"

static volatile sig_atomic_t g_stop = 0;

static void handle_stop_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static int open_listen_socket(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "listener: socket() failed: %s\n", strerror(errno));
        return -1;
    }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "listener: bind() on port %u failed: %s\n", port, strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, 16) != 0) {
        fprintf(stderr, "listener: listen() failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

static char *build_ack_json(const char *device_id, int64_t now) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, MDM_FIELD_PROTO_VERSION, MDM_PROTOCOL_VERSION);
    cJSON_AddNumberToObject(root, MDM_FIELD_MSG_KIND, MDM_MSG_HEARTBEAT_ACK);
    cJSON_AddStringToObject(root, MDM_FIELD_DEVICE_ID, device_id);
    cJSON_AddNumberToObject(root, MDM_FIELD_TIMESTAMP, (double)now);

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json;
}

static void handle_connection(int client_fd, const char *client_ip, mdm_registry_t *reg) {
    char *req_json = mdm_frame_recv(client_fd);
    if (req_json == NULL) {
        fprintf(stderr, "listener: failed to read frame from %s\n", client_ip);
        return;
    }

    cJSON *req = cJSON_Parse(req_json);
    free(req_json);
    if (req == NULL) {
        fprintf(stderr, "listener: malformed JSON from %s, rejecting\n", client_ip);
        return;
    }

    cJSON *kind = cJSON_GetObjectItemCaseSensitive(req, MDM_FIELD_MSG_KIND);
    cJSON *device_id = cJSON_GetObjectItemCaseSensitive(req, MDM_FIELD_DEVICE_ID);

    if (!cJSON_IsNumber(kind) || (int)kind->valuedouble != MDM_MSG_HEARTBEAT_REQ ||
        !cJSON_IsString(device_id) || device_id->valuestring[0] == '\0') {
        fprintf(stderr, "listener: malformed heartbeat from %s, rejecting\n", client_ip);
        cJSON_Delete(req);
        return;
    }

    int64_t now = (int64_t)time(NULL);
    printf("check-in: device_id='%s' from=%s at=%lld\n",
           device_id->valuestring, client_ip, (long long)now);

    if (mdm_registry_record_checkin(reg, device_id->valuestring, now) != 0) {
        fprintf(stderr, "listener: failed to record check-in for '%s'\n", device_id->valuestring);
    }

    char *resp_json = build_ack_json(device_id->valuestring, now);
    cJSON_Delete(req);

    if (resp_json != NULL) {
        mdm_frame_send(client_fd, resp_json, strlen(resp_json));
        free(resp_json);
    }
}

int mdm_listener_run(uint16_t port, mdm_registry_t *reg) {
    signal(SIGINT, handle_stop_signal);
    signal(SIGTERM, handle_stop_signal);

    int listen_fd = open_listen_socket(port);
    if (listen_fd < 0) {
        return -1;
    }

    printf("mdm-server: listening on port %u\n", port);

    while (!g_stop) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listen_fd, &readfds);
        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};

        int rc = select(listen_fd + 1, &readfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "listener: select() failed: %s\n", strerror(errno));
            break;
        }
        if (rc == 0) continue; /* timeout, re-check g_stop */

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "listener: accept() failed: %s\n", strerror(errno));
            continue;
        }

        char ip_str[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str));

        handle_connection(client_fd, ip_str, reg);
        close(client_fd);
    }

    close(listen_fd);
    printf("mdm-server: shutting down\n");
    return 0;
}
