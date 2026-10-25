#ifndef MDM_AGENT_INVENTORY_H
#define MDM_AGENT_INVENTORY_H

#include <stddef.h>
#include <stdint.h>

#include "cJSON.h"

typedef struct {
    char name[64];
    char ipv4[64];
} mdm_net_iface_t;

typedef struct {
    char hostname[256];
    char kernel_release[256];
    char kernel_version[256];

    char cpu_model[256];
    int  cpu_count;

    uint64_t mem_total_kb;
    uint64_t mem_available_kb;

    uint64_t disk_total_bytes;
    uint64_t disk_free_bytes;

    mdm_net_iface_t *ifaces;
    size_t           iface_count;

    double uptime_seconds;
    double load1;
    double load5;
    double load15;

    char  **logged_in_users;
    size_t  logged_in_user_count;

    char  **packages; /* each entry already formatted as "name version" */
    size_t  package_count;
} mdm_inventory_t;

/* Collects everything it can; a failed individual collector (e.g. no
 * /proc on this platform, package manager not found) just leaves its
 * fields zeroed and logs a warning — inventory is best-effort telemetry,
 * not a trust boundary, so partial results are fine. Always zeroes and
 * returns `inv` in a state safe to pass to mdm_inventory_free(). */
void mdm_inventory_collect(mdm_inventory_t *inv);

void mdm_inventory_free(mdm_inventory_t *inv);

/* Returns a new cJSON object owned by the caller (cJSON_Delete it, or
 * attach it into a parent object which then owns it). */
cJSON *mdm_inventory_to_json(const mdm_inventory_t *inv);

#endif /* MDM_AGENT_INVENTORY_H */
