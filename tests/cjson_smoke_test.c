/* Phase 0 acceptance check: vendored cJSON builds and links. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"

int main(void) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "hello", "world");

    char *out = cJSON_PrintUnformatted(root);
    int ok = out != NULL && strstr(out, "\"hello\":\"world\"") != NULL;

    printf("%s\n", out ? out : "(null)");
    free(out);
    cJSON_Delete(root);

    if (!ok) {
        fprintf(stderr, "cjson_smoke_test: FAILED\n");
        return 1;
    }
    printf("cjson_smoke_test: OK\n");
    return 0;
}
