#ifndef MDM_SERVER_REGISTRY_H
#define MDM_SERVER_REGISTRY_H

#include <sqlite3.h>
#include <stdint.h>

typedef struct {
    sqlite3 *db;
} mdm_registry_t;

/* Opens (creating if needed) the SQLite registry at db_path and ensures
 * the schema exists. Returns 0 on success, -1 on error. */
int mdm_registry_open(mdm_registry_t *reg, const char *db_path);

/* Records a check-in from a device that has only self-asserted its
 * identity (no client cert yet — that's Phase 3). Looks up the most
 * recent not-yet-enrolled row for this claimed_device_id and bumps
 * last_seen, or creates one. Phase 3 enrollment will promote this same
 * row (setting cert_fingerprint + status) rather than create a new one,
 * so the claimed_device_id is never treated as authoritative here.
 * Returns 0 on success, -1 on error. */
int mdm_registry_record_checkin(mdm_registry_t *reg, const char *claimed_device_id, int64_t now);

/* Stores `inventory_json` as the latest snapshot for the same row a
 * check-in would touch (see mdm_registry_record_checkin). Returns 0 on
 * success, -1 on error. */
int mdm_registry_store_inventory(mdm_registry_t *reg, const char *claimed_device_id,
                                  const char *inventory_json, int64_t now);

/* Looks up the most recently seen row for claimed_device_id and returns
 * its stored inventory JSON as a malloc'd string in *out_json (caller
 * frees). Returns 0 and sets *out_json on success, 1 if no row/snapshot
 * exists (with *out_json set to NULL), -1 on error. */
int mdm_registry_get_latest_inventory(mdm_registry_t *reg, const char *claimed_device_id,
                                       char **out_json);

void mdm_registry_close(mdm_registry_t *reg);

#endif /* MDM_SERVER_REGISTRY_H */
