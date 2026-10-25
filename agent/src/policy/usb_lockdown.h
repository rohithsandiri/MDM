#ifndef MDM_AGENT_POLICY_USB_LOCKDOWN_H
#define MDM_AGENT_POLICY_USB_LOCKDOWN_H

#include "cJSON.h"

/* Starts the udev monitor thread if it isn't already running. Safe to
 * call more than once — a no-op after the first. The thread always
 * runs; `enabled` (below) gates whether it actually blocks anything, so
 * toggling the policy on/off doesn't mean tearing down and rebuilding
 * the udev monitor each time. */
void mdm_policy_usb_lockdown_start(void);

/* Enables or disables lockdown per the verified command's params:
 * {"enabled": true|false}. While enabled, any USB mass-storage device
 * (ID_BUS=usb, subsystem=block) added after this call has its current
 * mount(s) forcibly removed, and a policy event is pushed (picked up on
 * the agent's next heartbeat). Returns 0 on success, -1 on error
 * (logged). */
int mdm_policy_usb_lockdown_apply(const cJSON *params);

#endif /* MDM_AGENT_POLICY_USB_LOCKDOWN_H */
