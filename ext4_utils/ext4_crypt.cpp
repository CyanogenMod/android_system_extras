/*
 * Copyright (c) 2015 Google, Inc.
 */

#define TAG "ext4_utils"

#include "ext4_crypt_init_extensions.h"

#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <sys/xattr.h>
#include <sys/syscall.h>
#include <sys/stat.h>

#include <cutils/klog.h>

#include "unencrypted_properties.h"

#define XATTR_NAME_ENCRYPTION_POLICY "encryption.policy"
#define EXT4_KEYREF_DELIMITER ((char)'.')

// ext4enc:TODO Include structure from somewhere sensible
// MUST be in sync with ext4_crypto.c in kernel
#define EXT4_MAX_KEY_SIZE 76
struct ext4_encryption_key {
        uint32_t mode;
        char raw[EXT4_MAX_KEY_SIZE];
        uint32_t size;
};

/* Validate that all path items are available and accessible. */
static int is_path_valid(const char *path)
{
    if (access(path, W_OK)) {
        KLOG_ERROR(TAG, "Can't access %s: %s\n",strerror(errno), path);
        return 0;
    }

    return 1;
}

/* Checks whether the policy provided is valid */
static int is_keyref_valid(const char *keyref)
{
    char *period = 0;
    size_t key_location_len = 0;

    /* Key ref must have a key and location delimiter character. */
    period = strchr(keyref, EXT4_KEYREF_DELIMITER);
    if (!period) {
        return 0;
    }

    /* period must be >= keyref. */
    key_location_len = period - keyref;

    if (strncmp(keyref, "@t", key_location_len) == 0 ||
        strncmp(keyref, "@p", key_location_len) == 0 ||
        strncmp(keyref, "@s", key_location_len) == 0 ||
        strncmp(keyref, "@u", key_location_len) == 0 ||
        strncmp(keyref, "@g", key_location_len) == 0 ||
        strncmp(keyref, "@us", key_location_len) == 0)
        return 1;

    return 0;
}

static int is_dir_empty(const char *dirname)
{
    int n = 0;
    struct dirent *d;
    DIR *dir;

    dir = opendir(dirname);
    while ((d = readdir(dir)) != NULL) {
        if (strcmp(d->d_name, "lost+found") == 0) {
            // Skip lost+found directory
        } else if (++n > 2) {
            break;
        }
    }
    closedir(dir);
    return n <= 2;
}

int do_policy_set(const char *directory, const char *policy)
{
    struct stat st;
    ssize_t ret;

    if (!is_keyref_valid(policy)) {
        KLOG_ERROR(TAG, "Policy has invalid format.\n");
        return -EINVAL;
    }

    if (!is_path_valid(directory)) {
        return -EINVAL;
    }

    stat(directory, &st);
    if (!S_ISDIR(st.st_mode)) {
        KLOG_ERROR(TAG, "Can only set policy on a directory (%s)\n", directory);
        return -EINVAL;
    }

    if (!is_dir_empty(directory)) {
        KLOG_ERROR(TAG, "Can only set policy on an empty directory (%s)\n",
                   directory);
        return -EINVAL;
    }

    ret = lsetxattr(directory, XATTR_NAME_ENCRYPTION_POLICY, policy,
                    strlen(policy), 0);

    if (ret) {
        KLOG_ERROR(TAG, "Failed to set encryption policy for %s: %s\n",
                   directory, strerror(errno));
        return -EINVAL;
    }

    KLOG_INFO(TAG, "Encryption policy for %s is set to %s\n", directory, policy);
    return 0;
}

bool e4crypt_non_default_key(const char* dir)
{
    UnencryptedProperties props(dir);
    return props.Get<int>(properties::is_default, 1) != 1;
}
