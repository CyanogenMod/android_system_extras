/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "ext4_crypt.h"

#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <fcntl.h>
#include <asm/ioctl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <cutils/properties.h>

#define XATTR_NAME_ENCRYPTION_POLICY "encryption.policy"
#define EXT4_KEYREF_DELIMITER ((char)'.')

// ext4enc:TODO Include structure from somewhere sensible
// MUST be in sync with ext4_crypto.c in kernel
#define EXT4_KEY_DESCRIPTOR_SIZE 8
#define EXT4_KEY_DESCRIPTOR_SIZE_HEX 17

struct ext4_encryption_policy {
    char version;
    char contents_encryption_mode;
    char filenames_encryption_mode;
    char flags;
    char master_key_descriptor[EXT4_KEY_DESCRIPTOR_SIZE];
} __attribute__((__packed__));

#define EXT4_ENCRYPTION_MODE_AES_256_XTS    1
#define EXT4_ENCRYPTION_MODE_AES_256_CTS    4
#define EXT4_ENCRYPTION_MODE_PRIVATE        127

// ext4enc:TODO Get value from somewhere sensible
#define EXT4_IOC_SET_ENCRYPTION_POLICY _IOR('f', 19, struct ext4_encryption_policy)
#define EXT4_IOC_GET_ENCRYPTION_POLICY _IOW('f', 21, struct ext4_encryption_policy)

#define HEX_LOOKUP "0123456789abcdef"

bool e4crypt_is_native() {
    char value[PROPERTY_VALUE_MAX];
    property_get("ro.crypto.type", value, "none");
    return !strcmp(value, "file");
}

static void policy_to_hex(const char* policy, char* hex) {
    for (size_t i = 0, j = 0; i < EXT4_KEY_DESCRIPTOR_SIZE; i++) {
        hex[j++] = HEX_LOOKUP[(policy[i] & 0xF0) >> 4];
        hex[j++] = HEX_LOOKUP[policy[i] & 0x0F];
    }
    hex[EXT4_KEY_DESCRIPTOR_SIZE_HEX - 1] = '\0';
}

static bool is_dir_empty(const char *dirname, bool *is_empty)
{
    int n = 0;
    auto dirp = std::unique_ptr<DIR, int (*)(DIR*)>(opendir(dirname), closedir);
    if (!dirp) {
        PLOG(ERROR) << "Unable to read directory: " << dirname;
        return false;
    }
    for (;;) {
        errno = 0;
        auto entry = readdir(dirp.get());
        if (!entry) {
            if (errno) {
                PLOG(ERROR) << "Unable to read directory: " << dirname;
                return false;
            }
            break;
        }
        if (strcmp(entry->d_name, "lost+found") != 0) { // Skip lost+found
            ++n;
            if (n > 2) {
                *is_empty = false;
                return true;
            }
        }
    }
    *is_empty = true;
    return true;
}

static bool e4crypt_policy_set(const char *directory, const char *policy,
                               size_t policy_length, int contents_encryption_mode) {
    if (policy_length != EXT4_KEY_DESCRIPTOR_SIZE) {
        LOG(ERROR) << "Policy wrong length: " << policy_length;
        return false;
    }
    int fd = open(directory, O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) {
        PLOG(ERROR) << "Failed to open directory " << directory;
        return false;
    }

    ext4_encryption_policy eep;
    eep.version = 0;
    eep.contents_encryption_mode = contents_encryption_mode;
    eep.filenames_encryption_mode = EXT4_ENCRYPTION_MODE_AES_256_CTS;
    eep.flags = 0;
    memcpy(eep.master_key_descriptor, policy, EXT4_KEY_DESCRIPTOR_SIZE);
    if (ioctl(fd, EXT4_IOC_SET_ENCRYPTION_POLICY, &eep)) {
        PLOG(ERROR) << "Failed to set encryption policy for " << directory;
        close(fd);
        return false;
    }
    close(fd);

    char policy_hex[EXT4_KEY_DESCRIPTOR_SIZE_HEX];
    policy_to_hex(policy, policy_hex);
    LOG(INFO) << "Policy for " << directory << " set to " << policy_hex;
    return true;
}

static bool e4crypt_policy_get(const char *directory, char *policy,
                               size_t policy_length, int contents_encryption_mode) {
    if (policy_length != EXT4_KEY_DESCRIPTOR_SIZE) {
        LOG(ERROR) << "Policy wrong length: " << policy_length;
        return false;
    }

    int fd = open(directory, O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) {
        PLOG(ERROR) << "Failed to open directory " << directory;
        return false;
    }

    ext4_encryption_policy eep;
    memset(&eep, 0, sizeof(ext4_encryption_policy));
    if (ioctl(fd, EXT4_IOC_GET_ENCRYPTION_POLICY, &eep) != 0) {
        PLOG(ERROR) << "Failed to get encryption policy for " << directory;
        close(fd);
        return -1;
    }
    close(fd);

    if ((eep.version != 0)
            || (eep.contents_encryption_mode != contents_encryption_mode)
            || (eep.filenames_encryption_mode != EXT4_ENCRYPTION_MODE_AES_256_CTS)
            || (eep.flags != 0)) {
        LOG(ERROR) << "Failed to find matching encryption policy for " << directory;
        return false;
    }
    memcpy(policy, eep.master_key_descriptor, EXT4_KEY_DESCRIPTOR_SIZE);

    return true;
}

static bool e4crypt_policy_check(const char *directory, const char *policy,
                                 size_t policy_length, int contents_encryption_mode) {
    if (policy_length != EXT4_KEY_DESCRIPTOR_SIZE) {
        LOG(ERROR) << "Policy wrong length: " << policy_length;
        return false;
    }
    char existing_policy[EXT4_KEY_DESCRIPTOR_SIZE];
    if (!e4crypt_policy_get(directory, existing_policy, EXT4_KEY_DESCRIPTOR_SIZE,
                            contents_encryption_mode)) return false;
    char existing_policy_hex[EXT4_KEY_DESCRIPTOR_SIZE_HEX];

    policy_to_hex(existing_policy, existing_policy_hex);

    if (memcmp(policy, existing_policy, EXT4_KEY_DESCRIPTOR_SIZE) != 0) {
        char policy_hex[EXT4_KEY_DESCRIPTOR_SIZE_HEX];
        policy_to_hex(policy, policy_hex);
        LOG(ERROR) << "Found policy " << existing_policy_hex << " at " << directory
                   << " which doesn't match expected value " << policy_hex;
        return false;
    }
    LOG(INFO) << "Found policy " << existing_policy_hex << " at " << directory
              << " which matches expected value";
    return true;
}

int e4crypt_policy_ensure(const char *directory, const char *policy,
                          size_t policy_length, const char* contents_encryption_mode) {
    int mode = 0;
    if (!strcmp(contents_encryption_mode, "software")) {
        mode = EXT4_ENCRYPTION_MODE_AES_256_XTS;
    } else if (!strcmp(contents_encryption_mode, "ice")) {
        mode = EXT4_ENCRYPTION_MODE_PRIVATE;
    } else {
        LOG(ERROR) << "Invalid encryption mode";
        return -1;
    }

    bool is_empty;
    if (!is_dir_empty(directory, &is_empty)) return -1;
    if (is_empty) {
        if (!e4crypt_policy_set(directory, policy, policy_length,
                                mode)) return -1;
    } else {
        if (!e4crypt_policy_check(directory, policy, policy_length,
                                  mode)) return -1;
    }
    return 0;
}
