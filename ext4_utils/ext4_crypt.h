#include <stdbool.h>
#include <sys/cdefs.h>
#include <sys/types.h>

__BEGIN_DECLS
// These functions assume they are being called from init
// They will not operate properly outside of init
int e4crypt_install_keyring();
int e4crypt_install_key(const char* dir);
int e4crypt_create_device_key(const char* dir,
                              int ensure_dir_exists(const char* dir));

// General functions
bool e4crypt_non_default_key(const char* dir);
int e4crypt_set_directory_policy(const char* dir);
int e4crypt_main(int argc, char* argv[]);
int e4crypt_change_password(const char* path, int crypt_type,
                            const char* password);
int e4crypt_get_password_type(const char* path);
int e4crypt_crypto_complete(const char* dir);
int e4crypt_check_passwd(const char* dir, const char* password);
const char* e4crypt_get_password(const char* dir);
int e4crypt_restart(const char* dir);

// Key functions. ext4enc:TODO Move to own file

// ext4enc:TODO - get these keyring standard definitions from proper system file
// keyring serial number type
typedef int32_t key_serial_t;

// special process keyring shortcut IDs
#define KEY_SPEC_THREAD_KEYRING       -1 // key ID for thread-specific keyring
#define KEY_SPEC_PROCESS_KEYRING      -2 // key ID for process-specific keyring
#define KEY_SPEC_SESSION_KEYRING      -3 // key ID for session-specific keyring
#define KEY_SPEC_USER_KEYRING         -4 // key ID for UID-specific keyring
#define KEY_SPEC_USER_SESSION_KEYRING -5 // key ID for UID-session keyring
#define KEY_SPEC_GROUP_KEYRING        -6 // key ID for GID-specific keyring

key_serial_t add_key(const char *type,
                     const char *description,
                     const void *payload,
                     size_t plen,
                     key_serial_t ringid);

long keyctl_setperm(key_serial_t id, int permissions);

// Set policy on directory
int do_policy_set(const char *directory, const char *policy);

__END_DECLS
