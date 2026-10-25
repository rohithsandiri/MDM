#ifndef MDM_AGENT_POLICY_FILE_INTEGRITY_H
#define MDM_AGENT_POLICY_FILE_INTEGRITY_H

#include "cJSON.h"

/* Starts the inotify watch thread if it isn't already running. Safe to
 * call more than once — a no-op after the first. */
void mdm_policy_file_integrity_start(void);

/* Adds or removes a watch per the verified command's params:
 *   {"action": "watch", "path": "/etc/passwd"}
 *   {"action": "unwatch", "path": "/etc/passwd"}
 * A detected modification on a watched path pushes a policy event (see
 * events.h), picked up on the agent's next heartbeat — it is only
 * reported, never auto-reverted in this phase. Returns 0 on success, -1
 * on error (logged). */
int mdm_policy_file_integrity_apply(const cJSON *params);

#endif /* MDM_AGENT_POLICY_FILE_INTEGRITY_H */
