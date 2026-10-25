#include "listener.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/x509.h>
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

SSL_CTX *mdm_tls_server_ctx_new(const char *ca_cert_path, const char *server_cert_path,
                                 const char *server_key_path) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        fprintf(stderr, "tls_server: SSL_CTX_new failed\n");
        return NULL;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_load_verify_locations(ctx, ca_cert_path, NULL) != 1) {
        fprintf(stderr, "tls_server: failed to load CA cert '%s'\n", ca_cert_path);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_certificate_file(ctx, server_cert_path, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "tls_server: failed to load server cert '%s'\n", server_cert_path);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, server_key_path, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "tls_server: failed to load server key '%s'\n", server_key_path);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "tls_server: server certificate/key mismatch\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* The actual enforcement: require a client certificate and verify it
     * against our CA. A client that presents nothing, or a cert that
     * doesn't chain to the CA, fails the handshake outright. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    return ctx;
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

static int compute_fingerprint_hex(X509 *cert, char *out, size_t out_size) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (X509_digest(cert, EVP_sha256(), digest, &digest_len) != 1) {
        return -1;
    }
    if (out_size < (size_t)digest_len * 2 + 1) {
        return -1;
    }
    for (unsigned int i = 0; i < digest_len; i++) {
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    }
    return 0;
}

static char *build_ack_json(const char *device_id, int64_t now, cJSON *pending_command) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, MDM_FIELD_PROTO_VERSION, MDM_PROTOCOL_VERSION);
    cJSON_AddNumberToObject(root, MDM_FIELD_MSG_KIND, MDM_MSG_HEARTBEAT_ACK);
    cJSON_AddStringToObject(root, MDM_FIELD_DEVICE_ID, device_id);
    cJSON_AddNumberToObject(root, MDM_FIELD_TIMESTAMP, (double)now);
    if (pending_command != NULL) {
        cJSON_AddItemToObject(root, MDM_FIELD_PENDING_COMMAND, pending_command);
    }

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json;
}

static void handle_connection(SSL *ssl, const char *client_ip, const char *fingerprint,
                               mdm_registry_t *reg) {
    char *req_json = mdm_frame_recv_tls(ssl);
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
    printf("check-in: fingerprint=%.16s claimed_device_id='%s' from=%s at=%lld\n",
           fingerprint, device_id->valuestring, client_ip, (long long)now);

    int64_t device_row_id = mdm_registry_upsert_enrolled(reg, fingerprint, device_id->valuestring, now);
    if (device_row_id < 0) {
        fprintf(stderr, "listener: failed to upsert device for fingerprint %.16s\n", fingerprint);
        cJSON_Delete(req);
        return;
    }

    cJSON *inventory = cJSON_GetObjectItemCaseSensitive(req, MDM_FIELD_INVENTORY);
    if (cJSON_IsObject(inventory)) {
        char *inv_json = cJSON_PrintUnformatted(inventory);
        if (inv_json != NULL) {
            if (mdm_registry_store_inventory(reg, device_row_id, inv_json, now) != 0) {
                fprintf(stderr, "listener: failed to store inventory for device_id=%lld\n",
                        (long long)device_row_id);
            } else {
                printf("inventory: stored snapshot for device_id=%lld (%zu bytes)\n",
                       (long long)device_row_id, strlen(inv_json));
            }
            free(inv_json);
        }
    }

    cJSON *policy_events = cJSON_GetObjectItemCaseSensitive(req, MDM_FIELD_POLICY_EVENTS);
    if (cJSON_IsArray(policy_events)) {
        cJSON *event = NULL;
        cJSON_ArrayForEach(event, policy_events) {
            cJSON *policy_type = cJSON_GetObjectItemCaseSensitive(event, MDM_FIELD_POLICY_TYPE);
            cJSON *message = cJSON_GetObjectItemCaseSensitive(event, MDM_FIELD_MESSAGE);
            cJSON *ts = cJSON_GetObjectItemCaseSensitive(event, MDM_FIELD_TIMESTAMP);
            printf("ALERT: device_id=%lld policy=%s at=%lld: %s\n", (long long)device_row_id,
                   cJSON_IsString(policy_type) ? policy_type->valuestring : "?",
                   cJSON_IsNumber(ts) ? (long long)ts->valuedouble : (long long)now,
                   cJSON_IsString(message) ? message->valuestring : "?");
        }
    }

    cJSON_Delete(req);

    cJSON *pending_command = NULL;
    char *pending_json = NULL;
    int rc = mdm_registry_pop_pending_command(reg, device_row_id, &pending_json);
    if (rc == 0) {
        pending_command = cJSON_Parse(pending_json);
        free(pending_json);
        if (pending_command == NULL) {
            fprintf(stderr, "listener: stored pending command for device_id=%lld is not valid JSON\n",
                    (long long)device_row_id);
        } else {
            printf("command: delivering queued command to device_id=%lld\n", (long long)device_row_id);
        }
    } else if (rc < 0) {
        fprintf(stderr, "listener: failed to check pending commands for device_id=%lld\n",
                (long long)device_row_id);
    }

    char *resp_json = build_ack_json(device_id->valuestring, now, pending_command);
    if (resp_json != NULL) {
        mdm_frame_send_tls(ssl, resp_json, strlen(resp_json));
        free(resp_json);
    }
}

int mdm_listener_run(uint16_t port, SSL_CTX *tls_ctx, mdm_registry_t *reg) {
    signal(SIGINT, handle_stop_signal);
    signal(SIGTERM, handle_stop_signal);

    int listen_fd = open_listen_socket(port);
    if (listen_fd < 0) {
        return -1;
    }

    printf("mdm-server: listening on port %u (mTLS required)\n", port);

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
        if (rc == 0) continue;

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

        SSL *ssl = SSL_new(tls_ctx);
        if (ssl == NULL) {
            fprintf(stderr, "listener: SSL_new failed for %s\n", ip_str);
            close(client_fd);
            continue;
        }
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) != 1) {
            fprintf(stderr, "listener: TLS handshake failed for %s (unauthenticated/invalid client "
                             "rejected)\n", ip_str);
            ERR_clear_error();
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        /* Belt-and-suspenders: don't rely solely on SSL_VERIFY_PEER having
         * fired during the handshake — check the result explicitly too. */
        long verify_result = SSL_get_verify_result(ssl);
        if (verify_result != X509_V_OK) {
            fprintf(stderr, "listener: client cert verification failed for %s: %s\n", ip_str,
                    X509_verify_cert_error_string(verify_result));
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        X509 *peer = SSL_get_peer_certificate(ssl);
        if (peer == NULL) {
            fprintf(stderr, "listener: %s presented no client certificate, rejecting\n", ip_str);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        char fingerprint[65];
        if (compute_fingerprint_hex(peer, fingerprint, sizeof(fingerprint)) != 0) {
            fprintf(stderr, "listener: failed to compute cert fingerprint for %s\n", ip_str);
            X509_free(peer);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_fd);
            continue;
        }
        X509_free(peer);

        handle_connection(ssl, ip_str, fingerprint, reg);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    close(listen_fd);
    printf("mdm-server: shutting down\n");
    return 0;
}
