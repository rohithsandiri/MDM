#ifndef MDM_AGENT_POLICY_FIREWALL_H
#define MDM_AGENT_POLICY_FIREWALL_H

#include "cJSON.h"

/* Applies or clears firewall rules via the `nft` binary (fixed path,
 * fixed argv — the ruleset text is fed to nft's own parser over a pipe,
 * never interpolated into a shell string). `params` is the verified
 * command's params object:
 *   {"action": "apply", "rules": ["tcp dport 22 accept", ...]}
 *   {"action": "clear"}
 * All managed rules live in one fixed table/chain (inet mdm_filter
 * input) that this module owns; `clear` flushes only that chain, never
 * touches the rest of the system's ruleset. Returns 0 on success, -1 on
 * error (logged). */
int mdm_policy_firewall_apply(const cJSON *params);

#endif /* MDM_AGENT_POLICY_FIREWALL_H */
