#include <stdio.h>
#include <string.h>

#include "version.h"

static void print_usage(const char *argv0) {
    fprintf(stderr, "usage: %s [--version]\n", argv0);
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--version") == 0) {
        printf("mdm-agent %s\n", MDM_VERSION);
        return 0;
    }

    print_usage(argv[0]);
    return 1;
}
