/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SYSTEM_DIRNAME  "/system/bin/"

// List of net utils wrapped by this program
// The list MUST be in descending order of string length
const char *netcmds[] = {
    "ip6tables",
    "iptables",
    "ndc",
    "tc",
    "ip",
    NULL,
};

// This is the only gateway for vendor programs to reach net utils.
int main(int /* argc */, char **argv) {
    char *progname = argv[0];
    char *basename = NULL;

    basename = strrchr(progname, '/');
    basename = basename ? basename + 1 : progname;

    for (int i = 0; netcmds[i]; ++i) {
        size_t len = strlen(netcmds[i]);
        if (!strncmp(basename, netcmds[i], len)) {
            // truncate to match netcmds[i]
            basename[len] = '\0';

            // hardcode the path to /system so it cannot be overwritten
            char *cmd;
            if (asprintf(&cmd, "%s%s", SYSTEM_DIRNAME, basename) == -1) {
                perror("asprintf");
                exit(EXIT_FAILURE);
            }
            argv[0] = cmd;
            execv(cmd, argv);
        }
    }

    // must never reach here
    fprintf(stderr, "(%s:%d) is not a supported net util\n", progname, errno);
    exit(EXIT_FAILURE);
}
