#include "events.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "messages.h"

typedef struct {
    char policy_type[32];
    char message[256];
    int64_t timestamp;
} mdm_policy_event_t;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static mdm_policy_event_t g_queue[MDM_POLICY_EVENT_CAPACITY];
static size_t g_count = 0;

void mdm_policy_events_init(void) {
    pthread_mutex_lock(&g_lock);
    g_count = 0;
    pthread_mutex_unlock(&g_lock);
}

void mdm_policy_events_push(const char *policy_type, const char *message) {
    pthread_mutex_lock(&g_lock);

    if (g_count == MDM_POLICY_EVENT_CAPACITY) {
        /* Drop the oldest to make room — telemetry, not a trust boundary. */
        memmove(&g_queue[0], &g_queue[1], (MDM_POLICY_EVENT_CAPACITY - 1) * sizeof(g_queue[0]));
        g_count--;
        fprintf(stderr, "policy_events: queue full, dropped oldest event\n");
    }

    mdm_policy_event_t *slot = &g_queue[g_count++];
    snprintf(slot->policy_type, sizeof(slot->policy_type), "%s", policy_type);
    snprintf(slot->message, sizeof(slot->message), "%s", message);
    slot->timestamp = (int64_t)time(NULL);

    pthread_mutex_unlock(&g_lock);
}

cJSON *mdm_policy_events_drain(void) {
    cJSON *arr = cJSON_CreateArray();

    pthread_mutex_lock(&g_lock);
    for (size_t i = 0; i < g_count; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, MDM_FIELD_POLICY_TYPE, g_queue[i].policy_type);
        cJSON_AddStringToObject(item, MDM_FIELD_MESSAGE, g_queue[i].message);
        cJSON_AddNumberToObject(item, MDM_FIELD_TIMESTAMP, (double)g_queue[i].timestamp);
        cJSON_AddItemToArray(arr, item);
    }
    g_count = 0;
    pthread_mutex_unlock(&g_lock);

    return arr;
}
