#include <sys/cdefs.h>
#include <stdbool.h>
#include <cutils/multiuser.h>

__BEGIN_DECLS

// These functions assume they are being called from init
// They will not operate properly outside of init
int e4crypt_install_keyring();
int e4crypt_create_device_key(const char* path,
                              int ensure_dir_exists(const char* dir));
int e4crypt_set_directory_policy(const char* path);
int e4crypt_do_init_user0();
int do_policy_set(const char *directory, const char *policy, int policy_length);

__END_DECLS
