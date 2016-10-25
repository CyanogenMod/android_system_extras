/*
 * Copyright (C) 2016 The Android Open Source Project
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

#define TAG "ext4_utils"

#include "ext4_crypt_init_extensions.h"
#include "ext4_crypt.h"

#include <android-base/logging.h>

#include <string>
#include <vector>

#include <dirent.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include <android-base/file.h>

#include <cutils/klog.h>
#include <cutils/properties.h>
#include <cutils/sockets.h>
#include <logwrap/logwrap.h>

#include "key_control.h"

static const std::string arbitrary_sequence_number = "42";
static const int vold_command_timeout_ms = 60 * 1000;

static void kernel_logger(android::base::LogId, android::base::LogSeverity severity, const char*,
        const char*, unsigned int, const char* message) {
    if (severity == android::base::ERROR || severity == android::base::FATAL) {
        KLOG_ERROR(TAG, "%s\n", message);
    } else if (severity == android::base::WARNING) {
        KLOG_WARNING(TAG, "%s\n", message);
    } else {
        KLOG_INFO(TAG, "%s\n", message);
    }
}

static void init_logging() {
    android::base::SetLogger(kernel_logger);
}

int e4crypt_create_device_key(const char* dir,
                              int ensure_dir_exists(const char*))
{
    init_logging();

    // Make sure folder exists. Use make_dir to set selinux permissions.
    std::string unencrypted_dir = std::string(dir) + e4crypt_unencrypted_folder;
    if (ensure_dir_exists(unencrypted_dir.c_str())) {
        KLOG_ERROR(TAG, "Failed to create %s (%s)\n",
                   unencrypted_dir.c_str(),
                   strerror(errno));
        return -1;
    }

    const char* argv[] = { "/system/bin/vdc", "--wait", "cryptfs", "enablefilecrypto" };
    int rc = android_fork_execvp(4, (char**) argv, NULL, false, true);
    LOG(INFO) << "enablefilecrypto result: " << rc;
    return rc;
}

int e4crypt_install_keyring()
{
    init_logging();

    key_serial_t device_keyring = add_key("keyring", "e4crypt", 0, 0,
                                          KEY_SPEC_SESSION_KEYRING);

    if (device_keyring == -1) {
        KLOG_ERROR(TAG, "Failed to create keyring (%s)\n", strerror(errno));
        return -1;
    }

    KLOG_INFO(TAG, "Keyring created with id %d in process %d\n",
              device_keyring, getpid());

    return 0;
}

int e4crypt_do_init_user0()
{
    init_logging();

    const char* argv[] = { "/system/bin/vdc", "--wait", "cryptfs", "init_user0" };
    int rc = android_fork_execvp(4, (char**) argv, NULL, false, true);
    LOG(INFO) << "init_user0 result: " << rc;
    return rc;
}

int e4crypt_set_directory_policy(const char* dir)
{
    init_logging();

    // Only set policy on first level /data directories
    // To make this less restrictive, consider using a policy file.
    // However this is overkill for as long as the policy is simply
    // to apply a global policy to all /data folders created via makedir
    if (!dir || strncmp(dir, "/data/", 6) || strchr(dir + 6, '/')) {
        return 0;
    }

    // Special case various directories that must not be encrypted,
    // often because their subdirectories must be encrypted.
    // This isn't a nice way to do this, see b/26641735
    std::vector<std::string> directories_to_exclude = {
        "lost+found",
        "system_ce", "system_de",
        "misc_ce", "misc_de",
        "media",
        "data", "user", "user_de",
    };
    std::string prefix = "/data/";
    for (auto d: directories_to_exclude) {
        if ((prefix + d) == dir) {
            KLOG_INFO(TAG, "Not setting policy on %s\n", dir);
            return 0;
        }
    }

    std::string ref_filename = std::string("/data") + e4crypt_key_ref;
    std::string policy;
    if (!android::base::ReadFileToString(ref_filename, &policy)) {
        KLOG_ERROR(TAG, "Unable to read system policy to set on %s\n", dir);
        return -1;
    }

    auto type_filename = std::string("/data") + e4crypt_key_mode;
    std::string contents_encryption_mode;
    if (!android::base::ReadFileToString(type_filename, &contents_encryption_mode)) {
        LOG(ERROR) << "Cannot read mode";
    }

    KLOG_INFO(TAG, "Setting policy on %s\n", dir);
    int result = e4crypt_policy_ensure(dir, policy.c_str(), policy.length(),
                                       contents_encryption_mode.c_str());
    if (result) {
        KLOG_ERROR(TAG, "Setting %02x%02x%02x%02x policy on %s failed!\n",
                   policy[0], policy[1], policy[2], policy[3], dir);
        return -1;
    }

    return 0;
}
