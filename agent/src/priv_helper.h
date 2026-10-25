#ifndef MDM_AGENT_PRIV_HELPER_H
#define MDM_AGENT_PRIV_HELPER_H

/* Internal argv[1] sentinel: when main() sees this, it's actually the
 * freshly-exec'd helper process, not a normal agent invocation. Never
 * documented to users — it's an implementation detail of how the main
 * loop and its privileged helper split out of one binary into two
 * processes. */
#define MDM_PRIV_HELPER_SENTINEL "__mdm_priv_helper__"

/* Forks and re-execs argv[0] with the sentinel above, handing the child
 * one end of a fresh socketpair (fd 3) and the trusted signing public
 * key's path via an environment variable. Must be called *before* the
 * caller drops privileges: the child inherits whatever privilege level
 * the process had at fork time (root, in a real deployment), and that's
 * the only privilege the helper will ever have — it is never raised
 * later. Returns the parent's end of the IPC socket (>= 0) on success,
 * -1 on failure (logged). A -1 here must be treated as fail-closed: no
 * helper means no privileged action can ever be performed, not a silent
 * fallback to running them unprivileged. */
int mdm_priv_helper_spawn(const char *self_path, const char *signing_pubkey_path);

/* Drops the *current* process's privileges to `user_name` and verifies
 * the drop actually took effect. Called in the parent, after spawning
 * the helper. If the process isn't running as root to begin with (e.g.
 * a dev/test container), logs a warning and returns 0 as a no-op rather
 * than failing, so the agent still runs somewhere without a root
 * invocation available. Returns 0 on success, -1 on a failed drop. */
int mdm_priv_drop_privileges(const char *user_name);

/* Entry point for the helper process. Reads signed command envelopes
 * from fd 3 in a loop, independently re-verifies each one against the
 * public key named by the environment variable mdm_priv_helper_spawn()
 * set, and dispatches the fixed command enum. This re-verification is
 * the actual trust boundary: the helper does not act on the unprivileged
 * process's say-so that a command already checked out. Returns when the
 * IPC channel closes (the parent exited or closed its end). */
int mdm_priv_helper_main(void);

#endif /* MDM_AGENT_PRIV_HELPER_H */
