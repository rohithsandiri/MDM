#include "priv_helper.h"

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "cJSON.h"
#include "crypto_verify.h"
#include "framing.h"
#include "messages.h"
#include "policy/events.h"
#include "policy/file_integrity.h"
#include "policy/firewall.h"
#include "policy/usb_lockdown.h"

#define MDM_HELPER_PUBKEY_ENV "MDM_SIGNING_PUBKEY_PATH"
#define MDM_HELPER_IPC_FD 3

int mdm_priv_helper_spawn(const char *self_path, const char *signing_pubkey_path) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        fprintf(stderr, "priv_helper: socketpair() failed: %s\n", strerror(errno));
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "priv_helper: fork() failed: %s\n", strerror(errno));
        close(sv[0]);
        close(sv[1]);
        return -1;
    }

    if (pid == 0) {
        close(sv[0]);
        if (dup2(sv[1], MDM_HELPER_IPC_FD) < 0) {
            _exit(127);
        }
        close(sv[1]);

        setenv(MDM_HELPER_PUBKEY_ENV, signing_pubkey_path, 1);

        char *helper_argv[] = {(char *)self_path, (char *)MDM_PRIV_HELPER_SENTINEL, NULL};
        execv(self_path, helper_argv);
        _exit(127); /* execv failed */
    }

    close(sv[1]);
    return sv[0];
}

int mdm_priv_drop_privileges(const char *user_name) {
    if (geteuid() != 0) {
        fprintf(stderr,
                "priv_helper: not running as root; skipping privilege drop "
                "(dev/test mode only — a real deployment must start the agent as root)\n");
        return 0;
    }

    struct passwd *pw = getpwnam(user_name);
    if (pw == NULL) {
        fprintf(stderr, "priv_helper: unprivileged user '%s' not found, refusing to continue\n",
                user_name);
        return -1;
    }

    if (setgroups(1, &pw->pw_gid) != 0 || setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
        fprintf(stderr, "priv_helper: failed to drop privileges to '%s': %s\n", user_name,
                strerror(errno));
        return -1;
    }

    if (geteuid() == 0 || getegid() == 0) {
        fprintf(stderr, "priv_helper: privilege drop did not take effect, refusing to continue\n");
        return -1;
    }

    printf("priv_helper: main loop dropped privileges to user '%s' (uid=%d)\n", user_name,
           (int)pw->pw_uid);
    return 0;
}

static const char *result_code_name(mdm_result_code_t rc) {
    switch (rc) {
        case MDM_RESULT_OK: return "ok";
        case MDM_RESULT_ERR_VERIFY_FAILED: return "verify_failed";
        case MDM_RESULT_ERR_MALFORMED: return "malformed";
        case MDM_RESULT_ERR_UNKNOWN_CMD: return "unknown_command";
        case MDM_RESULT_ERR_EXEC_FAILED: return "exec_failed";
        case MDM_RESULT_ERR_DENIED: return "denied";
        default: return "unknown";
    }
}

/* Fixed, enumerated dispatch — exhaustive over mdm_command_type_t, never
 * a string. The three policy commands are real as of Phase 4; lock/
 * reboot/wipe stay log-only stubs until Phase 5. */
static mdm_result_code_t dispatch_command(mdm_command_type_t type, cJSON *params) {
    switch (type) {
        case MDM_CMD_LOCK:
            printf("priv_helper: [stub] would lock all sessions now (Phase 5)\n");
            return MDM_RESULT_OK;
        case MDM_CMD_REBOOT:
            printf("priv_helper: [stub] would reboot the host now (Phase 5)\n");
            return MDM_RESULT_OK;
        case MDM_CMD_WIPE:
            printf("priv_helper: [stub] would wipe a target directory now (Phase 5)\n");
            return MDM_RESULT_OK;
        case MDM_CMD_POLICY_USB_LOCKDOWN:
            return mdm_policy_usb_lockdown_apply(params) == 0 ? MDM_RESULT_OK
                                                               : MDM_RESULT_ERR_EXEC_FAILED;
        case MDM_CMD_POLICY_FIREWALL:
            return mdm_policy_firewall_apply(params) == 0 ? MDM_RESULT_OK
                                                           : MDM_RESULT_ERR_EXEC_FAILED;
        case MDM_CMD_POLICY_FILE_INTEGRITY:
            return mdm_policy_file_integrity_apply(params) == 0 ? MDM_RESULT_OK
                                                                 : MDM_RESULT_ERR_EXEC_FAILED;
        case MDM_CMD_UNKNOWN:
        case MDM_CMD_COUNT:
        default:
            return MDM_RESULT_ERR_UNKNOWN_CMD;
    }
}

#define MDM_HELPER_POLL_EVENTS_FIELD "poll_events"

/* A local-only request from the main loop asking what its background
 * detection threads have queued — never signed, since it isn't an
 * action request at all, just the main loop reading its own helper's
 * telemetry back out. */
static int try_handle_poll_events(int fd, const char *request_json) {
    cJSON *req = cJSON_Parse(request_json);
    if (req == NULL) return 0;

    cJSON *poll = cJSON_GetObjectItemCaseSensitive(req, MDM_HELPER_POLL_EVENTS_FIELD);
    if (!cJSON_IsTrue(poll)) {
        cJSON_Delete(req);
        return 0;
    }
    cJSON_Delete(req);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddItemToObject(resp, MDM_FIELD_POLICY_EVENTS, mdm_policy_events_drain());
    char *resp_json = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);

    if (resp_json != NULL) {
        mdm_frame_send(fd, resp_json, strlen(resp_json));
        free(resp_json);
    }
    return 1;
}

static void handle_one_request(int fd, mdm_verifier_t *verifier, const char *envelope_json) {
    if (try_handle_poll_events(fd, envelope_json)) return;

    mdm_result_code_t result = MDM_RESULT_ERR_MALFORMED;

    cJSON *envelope = cJSON_Parse(envelope_json);
    if (envelope != NULL) {
        cJSON *signature = cJSON_GetObjectItemCaseSensitive(envelope, MDM_FIELD_SIGNATURE);
        cJSON *payload_field = cJSON_GetObjectItemCaseSensitive(envelope, MDM_FIELD_PAYLOAD);

        if (cJSON_IsString(signature) && cJSON_IsString(payload_field)) {
            const char *payload_bytes = payload_field->valuestring;
            size_t payload_len = strlen(payload_bytes);

            /* Independent re-verification: this process does not trust
             * that the unprivileged main loop already checked this. If
             * that process were compromised and forwarded something
             * unsigned or tampered, this is what stops it — the trust
             * boundary is the signature, not the sender. */
            int verify_rc =
                mdm_verifier_verify(verifier, payload_bytes, payload_len, signature->valuestring);
            if (verify_rc == 1) {
                cJSON *payload = cJSON_Parse(payload_bytes);
                if (payload != NULL) {
                    cJSON *cmd_type_item =
                        cJSON_GetObjectItemCaseSensitive(payload, MDM_FIELD_COMMAND_TYPE);
                    cJSON *expires_at_item =
                        cJSON_GetObjectItemCaseSensitive(payload, MDM_FIELD_EXPIRES_AT);
                    cJSON *params = cJSON_GetObjectItemCaseSensitive(payload, MDM_FIELD_PARAMS);

                    if (cJSON_IsNumber(cmd_type_item) && cJSON_IsNumber(expires_at_item)) {
                        int64_t expires_at = (int64_t)expires_at_item->valuedouble;
                        if ((int64_t)time(NULL) > expires_at) {
                            fprintf(stderr, "priv_helper: command expired, denying\n");
                            result = MDM_RESULT_ERR_DENIED;
                        } else {
                            result = dispatch_command(
                                (mdm_command_type_t)(int)cmd_type_item->valuedouble, params);
                        }
                    }
                    cJSON_Delete(payload);
                }
            } else {
                fprintf(stderr,
                        "priv_helper: independent signature re-verification failed, denying "
                        "(rc=%d)\n",
                        verify_rc);
                result = MDM_RESULT_ERR_VERIFY_FAILED;
            }
        }
        cJSON_Delete(envelope);
    } else {
        fprintf(stderr, "priv_helper: malformed envelope from main loop\n");
    }

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddNumberToObject(resp, MDM_FIELD_RESULT_CODE, result);
    cJSON_AddStringToObject(resp, MDM_FIELD_RESULT_MESSAGE, result_code_name(result));
    char *resp_json = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);

    if (resp_json != NULL) {
        mdm_frame_send(fd, resp_json, strlen(resp_json));
        free(resp_json);
    }
}

int mdm_priv_helper_main(void) {
    const char *pubkey_path = getenv(MDM_HELPER_PUBKEY_ENV);
    if (pubkey_path == NULL) {
        fprintf(stderr, "priv_helper: %s not set, refusing to start\n", MDM_HELPER_PUBKEY_ENV);
        return 1;
    }

    mdm_verifier_t verifier;
    if (mdm_verifier_load(&verifier, pubkey_path) != 0) {
        fprintf(stderr, "priv_helper: failed to load trusted signing public key, refusing to start\n");
        return 1;
    }

    mdm_policy_events_init();

    printf("priv_helper: ready (pid=%d, euid=%d)\n", (int)getpid(), (int)geteuid());

    for (;;) {
        char *req = mdm_frame_recv(MDM_HELPER_IPC_FD);
        if (req == NULL) {
            break; /* main loop closed the channel (exited, or lost the connection) */
        }
        handle_one_request(MDM_HELPER_IPC_FD, &verifier, req);
        free(req);
    }

    mdm_verifier_free(&verifier);
    printf("priv_helper: IPC channel closed, exiting\n");
    return 0;
}
