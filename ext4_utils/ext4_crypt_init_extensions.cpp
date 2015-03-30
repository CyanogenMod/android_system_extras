#define TAG "ext4_utils"

#include "ext4_crypt.h"

#include <string>
#include <fstream>
#include <iomanip>
#include <sstream>

#include <errno.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <cutils/klog.h>
#include <cutils/properties.h>
#include <cutils/sockets.h>

// ext4enc:TODO Include structure from somewhere sensible
// MUST be in sync with ext4_crypto.c in kernel
#define EXT4_MAX_KEY_SIZE 76
struct ext4_encryption_key {
        uint32_t mode;
        char raw[EXT4_MAX_KEY_SIZE];
        uint32_t size;
};

static const std::string unencrypted_path = "/unencrypted";
static const std::string keyring = "@s";
static const std::string arbitrary_sequence_number = "42";

static key_serial_t device_keyring = -1;

static std::string vold_command(std::string const& command)
{
    KLOG_INFO(TAG, "Running command %s\n", command.c_str());
    int sock = socket_local_client("vold",
                                   ANDROID_SOCKET_NAMESPACE_RESERVED,
                                   SOCK_STREAM);

    if (sock < 0) {
        KLOG_INFO(TAG, "Cannot open vold, failing command\n");
        return "";
    }

    class CloseSocket
    {
        int sock_;
    public:
        CloseSocket(int sock) : sock_(sock) {}
        ~CloseSocket() { close(sock_); }
    };

    CloseSocket cs(sock);

    // Use arbitrary sequence number. This should only be used when the
    // framework is down, so this is (mostly) OK.
    std::string actual_command = arbitrary_sequence_number + " " + command;
    if (write(sock, actual_command.c_str(), actual_command.size() + 1) < 0) {
        KLOG_ERROR(TAG, "Cannot write command\n");
        return "";
    }

    while (1) {
        struct timeval to;
        to.tv_sec = 10;
        to.tv_usec = 0;

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);

        int rc = select(sock + 1, &read_fds, NULL, NULL, &to);
        if (rc < 0) {
            KLOG_ERROR(TAG, "Error in select %s\n", strerror(errno));
            return "";
        } else if (!rc) {
            KLOG_ERROR(TAG, "Timeout\n");
            return "";
        } else if (FD_ISSET(sock, &read_fds)) {
            char buffer[4096];
            memset(buffer, 0, sizeof(buffer));
            rc = read(sock, buffer, sizeof(buffer));
            if (rc <= 0) {
                if (rc == 0) {
                    KLOG_ERROR(TAG, "Lost connection to Vold - did it crash?\n");
                } else {
                    KLOG_ERROR(TAG, "Error reading data (%s)\n", strerror(errno));
                }
                return "";
            }

            // We don't truly know that this is the correct result. However,
            // since this will only be used when the framework is down,
            // it should be OK unless someone is running vdc at the same time.
            // Worst case we force a reboot in the very rare synchronization
            // error
            return std::string(buffer, rc);
        }
    }
}

int e4crypt_create_device_key(const char* dir,
                              int ensure_dir_exists(const char*))
{
    // Make sure folder exists. Use make_dir to set selinux permissions.
    KLOG_INFO(TAG, "Creating test device key\n");
    std::string path = std::string() + dir + unencrypted_path;
    if (ensure_dir_exists(path.c_str())) {
        KLOG_ERROR(TAG, "Failed to create %s with error %s\n",
                   path.c_str(), strerror(errno));
        return -1;
    }

    // Open key if it exists
    std::string key_path = path + "/key";
    std::ifstream key(key_path.c_str(), std::ifstream::binary);

    if (!key.good()) {
        // Create new key if it doesn't
        std::ofstream new_key(key_path.c_str(), std::ofstream::binary);
        if (!new_key) {
            KLOG_ERROR(TAG, "Failed to open %s\n", key_path.c_str());
            return -1;
        }

        std::ifstream urandom("/dev/urandom", std::ifstream::binary);
        if (!urandom) {
            KLOG_ERROR(TAG, "Failed to open /dev/urandom\n");
            return -1;
        }

        char key_material[32];
        urandom.read(key_material, 32);
        if (!urandom) {
            KLOG_ERROR(TAG, "Failed to read random bytes\n");
            return -1;
        }

        new_key.write(key_material, 32);
        if (!new_key) {
            KLOG_ERROR(TAG, "Failed to write key material");
            return -1;
        }
    }

    remove((std::string(dir) + "/ref").c_str());
    return 0;
}

int e4crypt_install_keyring()
{
    device_keyring = add_key("keyring",
                             "e4crypt",
                             0,
                             0,
                             KEY_SPEC_SESSION_KEYRING);

    if (device_keyring == -1) {
        KLOG_ERROR(TAG, "Failed to create keyring\n");
        return -1;
    }

    KLOG_INFO(TAG, "Keyring created wth id %d in process %d\n", device_keyring, getpid());

    // ext4enc:TODO set correct permissions
    long result = keyctl_setperm(device_keyring, 0x3f3f3f3f);
    if (result) {
        KLOG_ERROR(TAG, "KEYCTL_SETPERM failed with error %ld\n", result);
        return -1;
    }

    return 0;
}

int e4crypt_install_key(const char* dir)
{
    std::string path = std::string() + dir + unencrypted_path;

    // Open key if it exists
    std::string key_path = path + "/key";
    std::ifstream key(key_path.c_str(), std::ifstream::binary);
    if (!key.good()) {
        KLOG_ERROR(TAG, "Failed to open key %s\n", key_path.c_str());
        return -1;
    }

    char keyblob[256];
    key.read(keyblob, sizeof(keyblob));
    std::streamsize keyblob_size = key.gcount();
    if (keyblob_size <= 0) {
        KLOG_ERROR(TAG, "Failed to read key data\n");
        return -1;
    }

    // Get password to decrypt as needed
    if (e4crypt_non_default_key(dir)) {
        std::string result = vold_command("cryptfs getpw");
        // result is either
        // 200 0 -1
        // or
        // 200 0 {{sensitive}} 0001020304
        // where 0001020304 is hex encoding of password
        std::istringstream i(result);
        std::string bit;
        i >> bit;
        if (bit != "200") {
            KLOG_ERROR(TAG, "Expecting 200\n");
            return -1;
        }

        i >> bit;
        if (bit != arbitrary_sequence_number) {
            KLOG_ERROR(TAG, "Expecting %s\n", arbitrary_sequence_number.c_str());
            return -1;
        }

        i >> bit;
        if (bit != "{{sensitive}}") {
            KLOG_INFO(TAG, "Not encrypted\n");
            return -1;
        }

        i >> bit;
    }

    // Add key to keyring
    ext4_encryption_key ext4_key = {0, {0}, 0};
    memcpy(ext4_key.raw, keyblob, keyblob_size);
    ext4_key.size = keyblob_size;

    // ext4enc:TODO Use better reference not 1234567890
    key_serial_t key_id = add_key("logon", "ext4-key:1234567890",
                                  (void*)&ext4_key, sizeof(ext4_key),
                                  device_keyring);

    if (key_id == -1) {
        KLOG_ERROR(TAG, "Failed to insert key into keyring with error %s\n",
                   strerror(errno));
        return -1;
    }

    KLOG_INFO(TAG, "Added key %d to keyring %d in process %d\n",
              key_id, device_keyring, getpid());

    // ext4enc:TODO set correct permissions
    long result = keyctl_setperm(key_id, 0x3f3f3f3f);
    if (result) {
        KLOG_ERROR(TAG, "KEYCTL_SETPERM failed with error %ld\n", result);
        return -1;
    }

    // Save reference to key so we can set policy later
    std::ofstream(path + "/ref") << "ext4-key:1234567890";
    return 0;
}

int e4crypt_set_directory_policy(const char* dir)
{
    // Only set policy on first level /data directories
    // ext4enc:TODO don't hard code /data/
    if (!dir || strncmp(dir, "/data/", 6) || strchr(dir + 6, '/')) {
        return 0;
    }

    std::ifstream ref_file("/data/unencrypted/ref");
    if (!ref_file) {
        KLOG_ERROR(TAG, "Cannot open key reference file\n");
        return -1;
    }

    std::string ref;
    std::getline(ref_file, ref);
    std::string policy = std::string() + keyring + "." + ref;
    KLOG_INFO(TAG, "Setting policy %s\n", policy.c_str());
    if (do_policy_set(dir, policy.c_str())) {
        KLOG_ERROR(TAG, "Setting policy on %s failed!", dir);
        return -1;
    }

    return 0;
}
