#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "crypto_verify.h"
#include "heartbeat.h"
#include "priv_helper.h"
#include "tls_client.h"
#include "version.h"

/* Resolves this process's own executable path for re-exec'ing itself as
 * the privileged helper (see priv_helper.c). /proc/self/exe is Linux-only
 * (the deployment target); argv[0] is kept as a fallback purely so this
 * still works when built/run ad hoc on a dev machine without /proc. */
static int resolve_self_path(char *out, size_t out_size) {
    ssize_t n = readlink("/proc/self/exe", out, out_size - 1);
    if (n > 0) {
        out[n] = '\0';
        return 0;
    }
    return -1;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--version") == 0) {
        printf("mdm-agent %s\n", MDM_VERSION);
        return 0;
    }

    if (argc >= 2 && strcmp(argv[1], MDM_PRIV_HELPER_SENTINEL) == 0) {
        return mdm_priv_helper_main();
    }

    mdm_agent_config_t cfg;
    if (mdm_config_parse_args(&cfg, argc, argv) != 0) {
        return 1;
    }

    SSL_CTX *tls_ctx =
        mdm_tls_client_ctx_new(cfg.ca_cert_path, cfg.client_cert_path, cfg.client_key_path);
    if (tls_ctx == NULL) {
        fprintf(stderr, "mdm-agent: failed to initialize TLS, exiting\n");
        return 1;
    }

    mdm_verifier_t verifier;
    if (mdm_verifier_load(&verifier, cfg.signing_pubkey_path) != 0) {
        fprintf(stderr, "mdm-agent: failed to load trusted signing public key, exiting\n");
        return 1;
    }

    char self_path[1024];
    const char *self_path_ptr = argv[0];
    if (resolve_self_path(self_path, sizeof(self_path)) == 0) {
        self_path_ptr = self_path;
    }

    /* Spawn the privileged helper BEFORE dropping privileges — it must
     * inherit whatever privilege level this process started with. */
    int helper_fd = mdm_priv_helper_spawn(self_path_ptr, cfg.signing_pubkey_path);
    if (helper_fd < 0) {
        fprintf(stderr, "mdm-agent: failed to start privileged helper, exiting (fail closed)\n");
        return 1;
    }

    if (mdm_priv_drop_privileges(cfg.unprivileged_user) != 0) {
        fprintf(stderr, "mdm-agent: failed to drop privileges, exiting (fail closed)\n");
        return 1;
    }

    int rc = mdm_heartbeat_run(&cfg, tls_ctx, &verifier, helper_fd);
    return rc == 0 ? 0 : 1;
}
