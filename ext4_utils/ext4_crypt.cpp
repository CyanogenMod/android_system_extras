#define TAG "ext4_utils"

#include "ext4_crypt.h"

#include <string>
#include <fstream>
#include <map>

#include <errno.h>
#include <sys/mount.h>

#include <cutils/klog.h>
#include <cutils/properties.h>

#include "unencrypted_properties.h"

namespace {
    std::map<std::string, std::string> s_password_store;
}

bool e4crypt_non_default_key(const char* dir)
{
    int type = e4crypt_get_password_type(dir);

    // ext4enc:TODO Use consts, not 1 here
    return type != -1 && type != 1;
}

int e4crypt_get_password_type(const char* path)
{
    UnencryptedProperties props(path);
    if (props.Get<std::string>(properties::key).empty()) {
        KLOG_INFO(TAG, "No master key, so not ext4enc\n");
        return -1;
    }

    return props.Get<int>(properties::type, 1);
}

int e4crypt_change_password(const char* path, int crypt_type,
                            const char* password)
{
    // ext4enc:TODO Encrypt master key with password securely. Store hash of
    // master key for validation
    UnencryptedProperties props(path);
    if (   props.Set(properties::password, password)
        && props.Set(properties::type, crypt_type))
        return 0;
    return -1;
}

int e4crypt_crypto_complete(const char* path)
{
    KLOG_INFO(TAG, "ext4 crypto complete called on %s\n", path);
    if (UnencryptedProperties(path).Get<std::string>(properties::key).empty()) {
        KLOG_INFO(TAG, "No master key, so not ext4enc\n");
        return -1;
    }

    return 0;
}

int e4crypt_check_passwd(const char* path, const char* password)
{
    UnencryptedProperties props(path);
    if (props.Get<std::string>(properties::key).empty()) {
        KLOG_INFO(TAG, "No master key, so not ext4enc\n");
        return -1;
    }

    auto actual_password = props.Get<std::string>(properties::password);

    if (actual_password == password) {
        s_password_store[path] = password;
        return 0;
    } else {
        return -1;
    }
}

int e4crypt_restart(const char* path)
{
    int rc = 0;

    KLOG_INFO(TAG, "ext4 restart called on %s\n", path);
    property_set("vold.decrypt", "trigger_reset_main");
    KLOG_INFO(TAG, "Just asked init to shut down class main\n");
    sleep(2);

    std::string tmp_path = std::string() + path + "/tmp_mnt";

    // ext4enc:TODO add retry logic
    rc = umount(tmp_path.c_str());
    if (rc) {
        KLOG_ERROR(TAG, "umount %s failed with rc %d, msg %s\n",
                   tmp_path.c_str(), rc, strerror(errno));
        return rc;
    }

    // ext4enc:TODO add retry logic
    rc = umount(path);
    if (rc) {
        KLOG_ERROR(TAG, "umount %s failed with rc %d, msg %s\n",
                   path, rc, strerror(errno));
        return rc;
    }

    return 0;
}

const char* e4crypt_get_password(const char* path)
{
    // ext4enc:TODO scrub password after timeout
    auto i = s_password_store.find(path);
    if (i == s_password_store.end()) {
        return 0;
    } else {
        return i->second.c_str();
    }
}
