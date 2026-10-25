#ifndef MDM_AGENT_HEARTBEAT_H
#define MDM_AGENT_HEARTBEAT_H

#include "config.h"

/* Runs the check-in loop in the foreground until interrupted (SIGINT/SIGTERM).
 * Returns 0 on clean shutdown, -1 on an unrecoverable setup error. */
int mdm_heartbeat_run(const mdm_agent_config_t *cfg);

#endif /* MDM_AGENT_HEARTBEAT_H */
