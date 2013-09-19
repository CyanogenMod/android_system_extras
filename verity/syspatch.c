/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "LzmaDec.h"

void usage()
{
    fprintf(stderr, "Usage: syspatch <patch> <target>\n");
}

int main(int argc, char *argv[])
{
    char *patch_path;
    char *target_path;

    int patch_fd;
    int target_fd;

    if (argc == 3) {
        patch_path = argv[1];
        target_path = argv[2];
    } else {
        usage();
        exit(-1);
    }

    patch_fd = open(patch_path, O_RDONLY);
    if (patch_fd < 0) {
        fprintf(stderr, "Couldn't open patch file (%s)\n", strerror(errno));
        exit(-1);
    }

    target_fd = open(target_path, O_RDWR);
    if (target_fd < 0) {
        fprintf(stderr, "Couldn't open target file (%s)\n", strerror(errno));
        exit(-1);
    }

    close(patch_fd);
    close(target_fd);
    exit(0);
}
