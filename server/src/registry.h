#ifndef MDM_SERVER_REGISTRY_H
#define MDM_SERVER_REGISTRY_H

#include <sqlite3.h>
#include <stdint.h>

typedef struct {
    sqlite3 *db;
} mdm_registry_t;

int mdm_registry_open(mdm_registry_t *reg, const char *db_path);
void mdm_registry_close(mdm_registry_t *reg);

/* The cert fingerprint from a verified mTLS handshake is now the
 * authoritative device identity (the handoff planned back in Phase 1).
 * Finds the row for `cert_fingerprint`, or — if a Phase 1/2 leftover row
 * exists with a matching claimed_device_id and no fingerprint yet —
 * promotes that row instead of creating a new one. Either way, bumps
 * last_seen and refreshes claimed_device_id (still stored, but purely
 * informational from here on). Returns the row id (>= 0) on success, -1
 * on error. */
int64_t mdm_registry_upsert_enrolled(mdm_registry_t *reg, const char *cert_fingerprint,
                                      const char *claimed_device_id, int64_t now);

int mdm_registry_store_inventory(mdm_registry_t *reg, int64_t device_row_id,
                                  const char *inventory_json, int64_t now);

/* Returns 0 and sets *out_json (malloc'd, caller frees) on success, 1 if
 * no such device/snapshot, -1 on error. */
int mdm_registry_get_latest_inventory(mdm_registry_t *reg, const char *cert_fingerprint,
                                       char **out_json);

int mdm_registry_find_by_fingerprint(mdm_registry_t *reg, const char *cert_fingerprint,
                                      int64_t *out_device_id);

/* Allocates the next strictly-increasing command sequence number for a
 * device — the actual replay-protection mechanism the agent enforces.
 * Returns 0 and sets *out_seq on success, -1 on error. */
int mdm_registry_next_sequence(mdm_registry_t *reg, int64_t device_row_id, int64_t *out_seq);

int mdm_registry_queue_command(mdm_registry_t *reg, int64_t device_row_id,
                                const char *signed_envelope_json, int64_t now);

/* Pops (marks delivered) the oldest undelivered command for a device.
 * Returns 0 and sets *out_json (malloc'd, caller frees) if one was
 * found, 1 if none pending, -1 on error. */
int mdm_registry_pop_pending_command(mdm_registry_t *reg, int64_t device_row_id, char **out_json);

/* Prints a table of all known devices to stdout (id, fingerprint prefix,
 * claimed_device_id, status, last_seen) for operator use. */
void mdm_registry_list_devices(mdm_registry_t *reg);

#endif /* MDM_SERVER_REGISTRY_H */
