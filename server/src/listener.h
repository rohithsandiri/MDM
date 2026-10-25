#ifndef MDM_SERVER_LISTENER_H
#define MDM_SERVER_LISTENER_H

#include <stdint.h>

#include "registry.h"

/* Runs a single-threaded, blocking accept loop on `port`, handling one
 * heartbeat connection at a time, until interrupted (SIGINT/SIGTERM).
 * Returns 0 on clean shutdown, -1 on an unrecoverable setup error. */
int mdm_listener_run(uint16_t port, mdm_registry_t *reg);

#endif /* MDM_SERVER_LISTENER_H */
