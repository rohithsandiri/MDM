#ifndef MDM_AGENT_POLICY_EVENTS_H
#define MDM_AGENT_POLICY_EVENTS_H

#include "cJSON.h"

/* Thread-safe queue of policy events, written by the helper's background
 * detection threads (USB/file-integrity) and drained by its single IPC
 * thread when the unprivileged main loop polls for them. Fixed capacity:
 * telemetry overflow drops the oldest event (logged), never blocks a
 * detection thread or grows without bound. */

#define MDM_POLICY_EVENT_CAPACITY 64

void mdm_policy_events_init(void);

/* Appends one event. `policy_type` is a short fixed label ("usb_lockdown",
 * "file_integrity"), `message` is a human-readable description. Safe to
 * call from any thread. */
void mdm_policy_events_push(const char *policy_type, const char *message);

/* Drains all currently queued events into a new cJSON array (caller owns
 * it — cJSON_Delete or attach it to a parent object). Never returns NULL;
 * an empty queue yields an empty array. */
cJSON *mdm_policy_events_drain(void);

#endif /* MDM_AGENT_POLICY_EVENTS_H */
