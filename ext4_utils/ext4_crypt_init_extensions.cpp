#define TAG "ext4_utils"

#include "ext4_crypt_init_extensions.h"

#include <string>

#include <dirent.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <cutils/klog.h>
#include <cutils/properties.h>
#include <cutils/sockets.h>
#include <poll.h>

#include "key_control.h"
#include "unencrypted_properties.h"

static const std::string arbitrary_sequence_number = "42";
static const int vold_command_timeout_ms = 60 * 1000;

static std::string vold_command(std::string const& command)
{
    KLOG_INFO(TAG, "Running command %s\n", command.c_str());
    int sock = -1;

    while (true) {
        sock = socket_local_client("cryptd",
                                   ANDROID_SOCKET_NAMESPACE_RESERVED,
                                   SOCK_STREAM);
        if (sock >= 0) {
            break;
        }
        usleep(10000);
    }

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

    struct pollfd poll_sock = {sock, POLLIN, 0};

    int rc = TEMP_FAILURE_RETRY(poll(&poll_sock, 1, vold_command_timeout_ms));
    if (rc < 0) {
        KLOG_ERROR(TAG, "Error in poll %s\n", strerror(errno));
        return "";
    }

    if (!(poll_sock.revents & POLLIN)) {
        KLOG_ERROR(TAG, "Timeout\n");
        return "";
    }
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));
    rc = TEMP_FAILURE_RETRY(read(sock, buffer, sizeof(buffer)));
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

int e4crypt_create_device_key(const char* dir,
                              int ensure_dir_exists(const char*))
{
    // Already encrypted with password? If so bail
    std::string temp_folder = std::string() + dir + "/tmp_mnt";
    DIR* temp_dir = opendir(temp_folder.c_str());
    if (temp_dir) {
        closedir(temp_dir);
        return 0;
    }

    // Make sure folder exists. Use make_dir to set selinux permissions.
    if (ensure_dir_exists(UnencryptedProperties::GetPath(dir).c_str())) {
        KLOG_ERROR(TAG, "Failed to create %s with error %s\n",
                   UnencryptedProperties::GetPath(dir).c_str(),
                   strerror(errno));
        return -1;
    }

    auto result = vold_command("cryptfs enablefilecrypto");
    // ext4enc:TODO proper error handling
    KLOG_INFO(TAG, "enablefilecrypto returned with result %s\n",
              result.c_str());

    return 0;
}

int e4crypt_install_keyring()
{
    key_serial_t device_keyring = add_key("keyring", "e4crypt", 0, 0,
                                          KEY_SPEC_SESSION_KEYRING);

    if (device_keyring == -1) {
        KLOG_ERROR(TAG, "Failed to create keyring\n");
        return -1;
    }

    KLOG_INFO(TAG, "Keyring created wth id %d in process %d\n",
              device_keyring, getpid());

    return 0;
}

int e4crypt_set_directory_policy(const char* dir)
{
    // Only set policy on first level /data directories
    // To make this less restrictive, consider using a policy file.
    // However this is overkill for as long as the policy is simply
    // to apply a global policy to all /data folders created via makedir
    if (!dir || strncmp(dir, "/data/", 6) || strchr(dir + 6, '/')) {
        return 0;
    }

    UnencryptedProperties props("/data");
    std::string policy = props.Get<std::string>(properties::ref);
    if (policy.empty()) {
        return 0;
    }

    KLOG_INFO(TAG, "Setting policy on %s\n", dir);
    int result = do_policy_set(dir, policy.c_str(), policy.size());
    if (result) {
        KLOG_ERROR(TAG, "Setting %s policy on %s failed!\n",
                   policy.c_str(), dir);
        return -1;
    }

    return 0;
}
