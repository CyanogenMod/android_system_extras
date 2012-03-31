/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef _MAKE_EXT4FS_H_
#define _MAKE_EXT4FS_H_

#include "ext4_utils.h"
#include "ext4.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#include <selinux/label.h>
#else
struct selabel_handle;
#endif

typedef void (*fs_config_func_t)(const char *path, int dir, unsigned *uid, unsigned *gid,
        unsigned *mode);

void reset_ext4fs_info();
int make_ext4fs(const char *filename, s64 len,
                const char *mountpoint, struct selabel_handle *sehnd);
int make_ext4fs_internal(int fd, const char *directory,
                         char *mountpoint, fs_config_func_t fs_config_func, int gzip, int sparse,
                         int crc, int wipe, int init_itabs, struct selabel_handle *sehnd);

#ifdef __cplusplus
}
#endif

#endif
