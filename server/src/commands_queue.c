#include "commands_queue.h"

#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "messages.h"

#define MDM_SERVER_SIGNER_KEY_ID "server-ed25519-v1"

static char *random_hex(size_t n_bytes) {
    unsigned char *raw = malloc(n_bytes);
    if (raw == NULL) return NULL;
    if (RAND_bytes(raw, (int)n_bytes) != 1) {
        free(raw);
        return NULL;
    }

    char *hex = malloc(n_bytes * 2 + 1);
    if (hex == NULL) {
        free(raw);
        return NULL;
    }
    for (size_t i = 0; i < n_bytes; i++) {
        snprintf(hex + i * 2, 3, "%02x", raw[i]);
    }
    free(raw);
    return hex;
}

int mdm_commands_queue(mdm_registry_t *reg, mdm_signer_t *signer, int64_t device_row_id,
                        int command_type, const char *params_json, int ttl_seconds, int64_t now) {
    int64_t sequence = 0;
    if (mdm_registry_next_sequence(reg, device_row_id, &sequence) != 0) {
        return -1;
    }

    char *command_id = random_hex(16);
    char *nonce = random_hex(16);
    if (command_id == NULL || nonce == NULL) {
        fprintf(stderr, "commands_queue: failed to generate command_id/nonce\n");
        free(command_id);
        free(nonce);
        return -1;
    }

    cJSON *payload = cJSON_CreateObject();
    cJSON_AddNumberToObject(payload, MDM_FIELD_COMMAND_TYPE, command_type);
    cJSON_AddStringToObject(payload, MDM_FIELD_COMMAND_ID, command_id);
    cJSON_AddNumberToObject(payload, MDM_FIELD_SEQUENCE, (double)sequence);
    cJSON_AddStringToObject(payload, MDM_FIELD_NONCE, nonce);
    cJSON_AddNumberToObject(payload, MDM_FIELD_ISSUED_AT, (double)now);
    cJSON_AddNumberToObject(payload, MDM_FIELD_EXPIRES_AT, (double)(now + ttl_seconds));

    cJSON *params = (params_json != NULL) ? cJSON_Parse(params_json) : cJSON_CreateObject();
    if (params == NULL) params = cJSON_CreateObject();
    cJSON_AddItemToObject(payload, MDM_FIELD_PARAMS, params);

    free(command_id);
    free(nonce);

    char *payload_text = cJSON_PrintUnformatted(payload);
    cJSON_Delete(payload);
    if (payload_text == NULL) {
        fprintf(stderr, "commands_queue: failed to serialize payload\n");
        return -1;
    }

    /* Sign the exact bytes that will be transmitted and verified — the
     * envelope below embeds `payload_text` verbatim as a JSON string, so
     * no re-serialization ever happens between signing and verifying. */
    char *signature_b64 = mdm_signer_sign_b64(signer, payload_text, strlen(payload_text));
    if (signature_b64 == NULL) {
        fprintf(stderr, "commands_queue: signing failed\n");
        free(payload_text);
        return -1;
    }

    cJSON *envelope = cJSON_CreateObject();
    cJSON_AddStringToObject(envelope, MDM_FIELD_SIGNER_KEY_ID, MDM_SERVER_SIGNER_KEY_ID);
    cJSON_AddStringToObject(envelope, MDM_FIELD_SIGNATURE, signature_b64);
    cJSON_AddStringToObject(envelope, MDM_FIELD_PAYLOAD, payload_text);
    free(payload_text);
    free(signature_b64);

    char *envelope_text = cJSON_PrintUnformatted(envelope);
    cJSON_Delete(envelope);
    if (envelope_text == NULL) {
        fprintf(stderr, "commands_queue: failed to serialize envelope\n");
        return -1;
    }

    int rc = mdm_registry_queue_command(reg, device_row_id, envelope_text, now);
    free(envelope_text);
    return rc;
}
