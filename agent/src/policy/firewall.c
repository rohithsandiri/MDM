#include "firewall.h"

#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "messages.h"

/* Idempotent setup, re-run on every apply/clear: ensures our table/chain
 * exist and starts from a clean slate — "apply" always means "replace
 * the whole managed ruleset", not "append to whatever was there". */
#define MDM_FW_TABLE_CHAIN_SETUP \
    "add table inet mdm_filter\n" \
    "add chain inet mdm_filter input { type filter hook input priority 0; }\n" \
    "flush chain inet mdm_filter input\n"

static const char *find_nft_path(void) {
    static const char *candidates[] = {"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"};
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (access(candidates[i], X_OK) == 0) return candidates[i];
    }
    return NULL;
}

/* Feeds `script` to `nft -f -` over a pipe, fixed argv — never a shell,
 * never string-interpolated into a command line. Returns 0 if nft
 * exited successfully, -1 otherwise (logged). */
static int run_nft_script(const char *script) {
    const char *nft_path = find_nft_path();
    if (nft_path == NULL) {
        fprintf(stderr, "policy_firewall: nft binary not found\n");
        return -1;
    }

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        fprintf(stderr, "policy_firewall: pipe() failed\n");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "policy_firewall: fork() failed\n");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[1]);
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);
        char *argv[] = {(char *)nft_path, "-f", "-", NULL};
        execv(nft_path, argv);
        _exit(127);
    }

    close(pipefd[0]);
    size_t len = strlen(script);
    size_t written = 0;
    while (written < len) {
        ssize_t n = write(pipefd[1], script + written, len - written);
        if (n <= 0) break;
        written += (size_t)n;
    }
    close(pipefd[1]);

    int status = 0;
    waitpid(pid, &status, 0);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "policy_firewall: nft exited with failure (status=%d)\n", status);
        return -1;
    }
    return 0;
}

int mdm_policy_firewall_apply(const cJSON *params) {
    const cJSON *action = cJSON_GetObjectItemCaseSensitive(params, MDM_PARAM_ACTION);
    if (!cJSON_IsString(action)) {
        fprintf(stderr, "policy_firewall: missing/invalid 'action' param\n");
        return -1;
    }

    char script[8192];
    size_t off = 0;
    off += (size_t)snprintf(script + off, sizeof(script) - off, "%s", MDM_FW_TABLE_CHAIN_SETUP);

    if (strcmp(action->valuestring, "apply") == 0) {
        const cJSON *rules = cJSON_GetObjectItemCaseSensitive(params, MDM_PARAM_RULES);
        if (!cJSON_IsArray(rules)) {
            fprintf(stderr, "policy_firewall: 'apply' requires a 'rules' array\n");
            return -1;
        }
        const cJSON *rule = NULL;
        cJSON_ArrayForEach(rule, rules) {
            if (!cJSON_IsString(rule)) continue;
            int n = snprintf(script + off, sizeof(script) - off,
                              "add rule inet mdm_filter input %s\n", rule->valuestring);
            if (n < 0 || (size_t)n >= sizeof(script) - off) {
                fprintf(stderr, "policy_firewall: ruleset too large, truncating\n");
                break;
            }
            off += (size_t)n;
        }
    } else if (strcmp(action->valuestring, "clear") != 0) {
        fprintf(stderr, "policy_firewall: unknown action '%s'\n", action->valuestring);
        return -1;
    }

    printf("policy_firewall: applying nft script:\n%s", script);
    return run_nft_script(script);
}
