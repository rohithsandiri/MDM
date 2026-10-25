#include "commands.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "framing.h"
#include "messages.h"

static int64_t load_last_sequence(const char *state_file_path) {
    FILE *f = fopen(state_file_path, "r");
    if (f == NULL) return 0; /* no state yet — first command is always sequence > 0 */

    long long v = 0;
    if (fscanf(f, "%lld", &v) != 1) v = 0;
    fclose(f);
    return (int64_t)v;
}

static int save_last_sequence(const char *state_file_path, int64_t seq) {
    FILE *f = fopen(state_file_path, "w");
    if (f == NULL) {
        fprintf(stderr, "commands: failed to persist replay state to '%s': %s\n", state_file_path,
                strerror(errno));
        return -1;
    }
    fprintf(f, "%lld\n", (long long)seq);
    fclose(f);
    return 0;
}

void mdm_commands_handle_envelope(const char *envelope_json, mdm_verifier_t *verifier,
                                   int helper_fd, const char *state_file_path) {
    cJSON *envelope = cJSON_Parse(envelope_json);
    if (envelope == NULL) {
        fprintf(stderr, "commands: malformed envelope JSON, rejecting\n");
        return;
    }

    cJSON *signature = cJSON_GetObjectItemCaseSensitive(envelope, MDM_FIELD_SIGNATURE);
    cJSON *payload_field = cJSON_GetObjectItemCaseSensitive(envelope, MDM_FIELD_PAYLOAD);
    if (!cJSON_IsString(signature) || !cJSON_IsString(payload_field)) {
        fprintf(stderr, "commands: envelope missing signature/payload, rejecting\n");
        cJSON_Delete(envelope);
        return;
    }

    /* The exact decoded bytes of the "payload" string field — never a
     * re-serialization of a parsed object. Verified before any parsing
     * of their content happens. */
    const char *payload_bytes = payload_field->valuestring;
    size_t payload_len = strlen(payload_bytes);

    int verify_rc = mdm_verifier_verify(verifier, payload_bytes, payload_len, signature->valuestring);
    if (verify_rc != 1) {
        fprintf(stderr, "commands: signature verification failed (rc=%d), rejecting command\n",
                verify_rc);
        cJSON_Delete(envelope);
        return;
    }

    cJSON *payload = cJSON_Parse(payload_bytes);
    if (payload == NULL) {
        fprintf(stderr, "commands: verified payload is not valid JSON, rejecting\n");
        cJSON_Delete(envelope);
        return;
    }

    cJSON *seq_item = cJSON_GetObjectItemCaseSensitive(payload, MDM_FIELD_SEQUENCE);
    cJSON *issued_at_item = cJSON_GetObjectItemCaseSensitive(payload, MDM_FIELD_ISSUED_AT);
    cJSON *expires_at_item = cJSON_GetObjectItemCaseSensitive(payload, MDM_FIELD_EXPIRES_AT);
    cJSON *cmd_type_item = cJSON_GetObjectItemCaseSensitive(payload, MDM_FIELD_COMMAND_TYPE);
    cJSON *nonce_item = cJSON_GetObjectItemCaseSensitive(payload, MDM_FIELD_NONCE);

    if (!cJSON_IsNumber(seq_item) || !cJSON_IsNumber(issued_at_item) ||
        !cJSON_IsNumber(expires_at_item) || !cJSON_IsNumber(cmd_type_item)) {
        fprintf(stderr, "commands: payload missing required replay-protection fields, rejecting\n");
        cJSON_Delete(payload);
        cJSON_Delete(envelope);
        return;
    }

    int64_t sequence = (int64_t)seq_item->valuedouble;
    int64_t expires_at = (int64_t)expires_at_item->valuedouble;
    int64_t now = (int64_t)time(NULL);

    /* The actual replay defense: strictly increasing, persisted. A
     * signature being valid proves authenticity, not freshness — this is
     * what stops a captured-and-replayed signed command from acting
     * twice. */
    int64_t last_seq = load_last_sequence(state_file_path);
    if (sequence <= last_seq) {
        fprintf(stderr,
                "commands: sequence %lld is not greater than last accepted %lld — replay or "
                "stale command, rejecting\n",
                (long long)sequence, (long long)last_seq);
        cJSON_Delete(payload);
        cJSON_Delete(envelope);
        return;
    }
    if (now > expires_at) {
        fprintf(stderr, "commands: command expired (now=%lld, expires_at=%lld), rejecting\n",
                (long long)now, (long long)expires_at);
        cJSON_Delete(payload);
        cJSON_Delete(envelope);
        return;
    }

    printf("commands: accepted command_type=%d sequence=%lld nonce=%s\n",
           (int)cmd_type_item->valuedouble, (long long)sequence,
           cJSON_IsString(nonce_item) ? nonce_item->valuestring : "?");

    if (save_last_sequence(state_file_path, sequence) != 0) {
        fprintf(stderr, "commands: could not persist replay state — refusing to execute "
                        "(fail closed)\n");
        cJSON_Delete(payload);
        cJSON_Delete(envelope);
        return;
    }
    cJSON_Delete(payload);

    if (helper_fd < 0) {
        fprintf(stderr, "commands: no privileged helper available, cannot execute\n");
        cJSON_Delete(envelope);
        return;
    }

    /* Forward the ORIGINAL raw envelope bytes, unchanged, so the helper's
     * independent re-verification covers the exact same bytes this
     * process just checked. */
    if (mdm_frame_send(helper_fd, envelope_json, strlen(envelope_json)) != 0) {
        fprintf(stderr, "commands: failed to forward command to privileged helper\n");
    } else {
        char *helper_resp = mdm_frame_recv(helper_fd);
        if (helper_resp != NULL) {
            printf("commands: helper response: %s\n", helper_resp);
            free(helper_resp);
        } else {
            fprintf(stderr, "commands: no response from privileged helper\n");
        }
    }

    cJSON_Delete(envelope);
}
